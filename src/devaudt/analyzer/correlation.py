"""
analyzer/correlation.py — Evidence Correlation Engine.

Consumes a ``RiskReport`` (produced by ``RiskScoringEngine``) and groups
``WeightedRiskProfile`` items into ``ClusterProfile`` objects — cohesive sets
of entities that are failing together, so an LLM or human reviewer can focus
on a single narrative instead of a flat list of findings.

Clustering rules (applied in priority order)
--------------------------------------------
1. File cluster     — All profiles sharing the same source file.
2. Caller cluster   — Profiles whose files are connected via
                       ``AuditContext.callers`` / ``callees`` edges.

A cluster is formed from any connected component of ≥ 2 profiles.
Components with exactly 2 members are emitted only when their combined
``total_pain`` exceeds ``MIN_PAIR_PAIN`` (default 40).  Single-member
components are reported in ``CorrelationReport.unclustered``.

Hotspot detection
-----------------
A cluster is promoted to ``is_hotspot = True`` when it meets ANY of:
  • ≥ 3 members
  • combined security issues > 0  AND  total issues ≥ 3
  • peak_pain ≥ 50

Output
------
``ClusterProfile`` gives an LLM-ready ``narrative`` such as:
    "3 functions in auth.py are failing together: SQL Injection (security),
     two Large Class smells (maintainability), and a deep nesting issue
     (performance). Combined pain score: 142.3."
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .risk import RiskReport, WeightedRiskProfile

# ---------------------------------------------------------------------------
# Tuneable thresholds
# ---------------------------------------------------------------------------

# Minimum combined pain for a two-member cluster to be emitted
MIN_PAIR_PAIN: float = 40.0

# Minimum members for a cluster to be promoted to hotspot by count alone
HOTSPOT_MIN_MEMBERS: int = 3

# Peak pain threshold for two-member clusters to be promoted to hotspot
HOTSPOT_PEAK_PAIN: float = 50.0


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ClusterProfile:
    """A cohesive group of entities that are failing together."""

    cluster_id: str = ""                        # Stable hash of sorted member entity_ids
    cluster_kind: str = "file_hotspot"          # file_hotspot | caller_chain | mixed
    anchor_file: str = ""                       # Primary / most-painful file in the cluster
    rank: int = 0                               # 1 = highest combined pain

    members: list[str] = field(default_factory=list)            # entity_ids
    member_names: list[str] = field(default_factory=list)       # human-readable names
    member_files: list[str] = field(default_factory=list)       # unique source files

    # Aggregate scores
    total_pain: float = 0.0                     # sum of member pain_scores
    peak_pain: float = 0.0                      # max pain_score in cluster
    avg_pain: float = 0.0

    # Issue breakdown
    total_issues: int = 0
    total_smells: int = 0
    issue_kind_totals: dict[str, int] = field(default_factory=dict)
    has_security: bool = False

    # Promotion flag
    is_hotspot: bool = False

    # LLM-ready explanation
    narrative: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id":        self.cluster_id,
            "cluster_kind":      self.cluster_kind,
            "anchor_file":       self.anchor_file,
            "rank":              self.rank,
            "is_hotspot":        self.is_hotspot,
            "members":           self.members,
            "member_names":      self.member_names,
            "member_files":      self.member_files,
            "total_pain":        round(self.total_pain, 1),
            "peak_pain":         round(self.peak_pain, 1),
            "avg_pain":          round(self.avg_pain, 1),
            "total_issues":      self.total_issues,
            "total_smells":      self.total_smells,
            "issue_kind_totals": self.issue_kind_totals,
            "has_security":      self.has_security,
            "narrative":         self.narrative,
        }


@dataclass
class CorrelationReport:
    """Repository-level correlation output from EvidenceCorrelationEngine."""

    clusters: list[ClusterProfile] = field(default_factory=list)
    unclustered: list[str] = field(default_factory=list)    # entity_ids not in any cluster
    summary: dict[str, Any] = field(default_factory=dict)
    generated_at: str = ""
    total_clusters: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at":   self.generated_at,
            "total_clusters": self.total_clusters,
            "summary":        self.summary,
            "clusters":       [c.to_dict() for c in self.clusters],
            "unclustered":    self.unclustered,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class EvidenceCorrelationEngine:
    """
    Transforms a ``RiskReport`` into a ``CorrelationReport``.

    Usage::

        from devaudt.analyzer.correlation import EvidenceCorrelationEngine
        report = EvidenceCorrelationEngine().correlate(risk_report)
        print(report.to_dict())
    """

    def correlate(self, risk_report: RiskReport) -> CorrelationReport:
        """Return a fully populated ``CorrelationReport`` for *risk_report*."""
        profiles = risk_report.profiles
        if not profiles:
            return CorrelationReport(
                generated_at=_now_iso(),
                summary=self._empty_summary(),
            )

        # ----------------------------------------------------------------
        # Build adjacency: entity_id → set of connected entity_ids
        # ----------------------------------------------------------------
        # Index for fast lookup
        by_entity: dict[str, WeightedRiskProfile] = {p.entity_id: p for p in profiles}
        all_eids = set(by_entity)

        # Rule 1 — Same file
        by_file: dict[str, list[str]] = defaultdict(list)
        for p in profiles:
            if p.file:
                by_file[p.file].append(p.entity_id)

        # file → set of entity_ids in that file
        adj: dict[str, set[str]] = defaultdict(set)

        for eid_list in by_file.values():
            for i, a in enumerate(eid_list):
                for b in eid_list[i + 1:]:
                    adj[a].add(b)
                    adj[b].add(a)

        # Rule 2 — Caller / callee edges
        # file → entity_ids that live in it
        file_to_eids: dict[str, set[str]] = defaultdict(set)
        for p in profiles:
            if p.file:
                file_to_eids[p.file].add(p.entity_id)

        for p in profiles:
            # Profiles whose entity is called by p (p imports them)
            for callee_file in p.callees:
                for neighbor_eid in file_to_eids.get(callee_file, []):
                    if neighbor_eid != p.entity_id:
                        adj[p.entity_id].add(neighbor_eid)
                        adj[neighbor_eid].add(p.entity_id)
            # Profiles that call p (they import p's file)
            for caller_file in p.callers:
                for neighbor_eid in file_to_eids.get(caller_file, []):
                    if neighbor_eid != p.entity_id:
                        adj[p.entity_id].add(neighbor_eid)
                        adj[neighbor_eid].add(p.entity_id)

        # ----------------------------------------------------------------
        # Connected-component BFS
        # ----------------------------------------------------------------
        visited: set[str] = set()
        components: list[list[str]] = []

        for start in sorted(all_eids):  # sorted for determinism
            if start in visited:
                continue
            component: list[str] = []
            queue = [start]
            while queue:
                node = queue.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                component.append(node)
                queue.extend(adj.get(node, set()) - visited)
            components.append(sorted(component))  # stable order

        # ----------------------------------------------------------------
        # Build ClusterProfile for each qualifying component
        # ----------------------------------------------------------------
        clusters: list[ClusterProfile] = []
        unclustered: list[str] = []

        for component in components:
            if len(component) == 1:
                unclustered.append(component[0])
                continue

            member_profiles = [by_entity[eid] for eid in component]
            total_pain = round(sum(p.pain_score for p in member_profiles), 1)
            peak_pain  = max(p.pain_score for p in member_profiles)
            avg_pain   = round(total_pain / len(member_profiles), 1)

            # Drop weak pairs
            if len(component) == 2 and total_pain < MIN_PAIR_PAIN:
                unclustered.extend(component)
                continue

            # Aggregate issue breakdowns
            kind_totals: dict[str, int] = defaultdict(int)
            total_issues = 0
            total_smells = 0
            for p in member_profiles:
                total_issues += p.issue_count
                total_smells += p.smell_count
                for k, c in p.issue_kinds.items():
                    kind_totals[k] += c

            has_security = kind_totals.get("security", 0) > 0

            # Hotspot promotion
            is_hotspot = (
                len(component) >= HOTSPOT_MIN_MEMBERS
                or (has_security and (total_issues + total_smells) >= 3)
                or peak_pain >= HOTSPOT_PEAK_PAIN
            )

            # Anchor: the file belonging to the highest-pain member
            anchor_profile = max(member_profiles, key=lambda p: p.pain_score)
            anchor_file = anchor_profile.file or anchor_profile.entity_id

            # Unique files (order by descending max pain in that file)
            pain_by_file: dict[str, float] = defaultdict(float)
            for p in member_profiles:
                pain_by_file[p.file] += p.pain_score
            member_files = sorted(
                {p.file for p in member_profiles if p.file},
                key=lambda f: -pain_by_file[f],
            )

            # cluster_kind
            unique_files_count = len(member_files)
            if unique_files_count == 1:
                cluster_kind = "file_hotspot"
            elif any(p.callers or p.callees for p in member_profiles):
                cluster_kind = "caller_chain"
            else:
                cluster_kind = "mixed"

            # Stable cluster_id
            cluster_id = _stable_id(component)

            narrative = _build_narrative(
                member_profiles=member_profiles,
                anchor_file=anchor_file,
                cluster_kind=cluster_kind,
                kind_totals=dict(kind_totals),
                total_pain=total_pain,
                is_hotspot=is_hotspot,
            )

            clusters.append(
                ClusterProfile(
                    cluster_id=cluster_id,
                    cluster_kind=cluster_kind,
                    anchor_file=anchor_file,
                    members=component,
                    member_names=[by_entity[eid].name or eid for eid in component],
                    member_files=member_files,
                    total_pain=total_pain,
                    peak_pain=round(peak_pain, 1),
                    avg_pain=avg_pain,
                    total_issues=total_issues,
                    total_smells=total_smells,
                    issue_kind_totals=dict(kind_totals),
                    has_security=has_security,
                    is_hotspot=is_hotspot,
                    narrative=narrative,
                )
            )

        # Sort by total_pain desc, cluster_id asc for stability
        clusters.sort(key=lambda c: (-c.total_pain, c.cluster_id))
        for i, c in enumerate(clusters, start=1):
            c.rank = i

        summary = self._build_summary(clusters, unclustered, risk_report)

        return CorrelationReport(
            clusters=clusters,
            unclustered=unclustered,
            summary=summary,
            generated_at=_now_iso(),
            total_clusters=len(clusters),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        clusters: list[ClusterProfile],
        unclustered: list[str],
        risk_report: RiskReport,
    ) -> dict[str, Any]:
        if not clusters:
            return EvidenceCorrelationEngine._empty_summary()

        hotspots = [c for c in clusters if c.is_hotspot]
        top3 = [
            {
                "rank": c.rank,
                "cluster_id": c.cluster_id,
                "anchor_file": c.anchor_file,
                "total_pain": c.total_pain,
                "members": len(c.members),
                "is_hotspot": c.is_hotspot,
            }
            for c in clusters[:3]
        ]

        # Hotspot files (anchor files of hotspot clusters)
        hotspot_files = list({c.anchor_file for c in hotspots})[:10]

        total_clustered = sum(len(c.members) for c in clusters)

        return {
            "total_clusters":    len(clusters),
            "hotspot_clusters":  len(hotspots),
            "unclustered_count": len(unclustered),
            "total_clustered":   total_clustered,
            "top_clusters":      top3,
            "hotspot_files":     hotspot_files,
            "total_pain_in_clusters": round(sum(c.total_pain for c in clusters), 1),
        }

    @staticmethod
    def _empty_summary() -> dict[str, Any]:
        return {
            "total_clusters":    0,
            "hotspot_clusters":  0,
            "unclustered_count": 0,
            "total_clustered":   0,
            "top_clusters":      [],
            "hotspot_files":     [],
            "total_pain_in_clusters": 0.0,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stable_id(members: list[str]) -> str:
    """Deterministic 8-char hex ID from sorted member entity_ids."""
    h = hashlib.sha1(",".join(sorted(members)).encode(), usedforsecurity=False)
    return "CLST-" + h.hexdigest()[:8].upper()


def _build_narrative(
    *,
    member_profiles: list[WeightedRiskProfile],
    anchor_file: str,
    cluster_kind: str,
    kind_totals: dict[str, int],
    total_pain: float,
    is_hotspot: bool,
) -> str:
    n = len(member_profiles)
    names = [p.name or p.entity_id for p in member_profiles]

    # Lead sentence
    if cluster_kind == "file_hotspot":
        location = f"in {anchor_file}"
    elif cluster_kind == "caller_chain":
        location = f"connected to {anchor_file} via import chain"
    else:
        location = f"spanning multiple files including {anchor_file}"

    if is_hotspot:
        lead = f"{n} entit{'y' if n == 1 else 'ies'} {location} are failing together"
    else:
        lead = f"{n} related entit{'y' if n == 1 else 'ies'} {location}"

    # Issue breakdown
    parts: list[str] = []
    for kind in ("security", "performance", "maintainability", "reliability", "unknown"):
        count = kind_totals.get(kind, 0)
        if count:
            parts.append(f"{count} {kind} issue{'s' if count > 1 else ''}")
    # Any remaining kinds not in the above list
    for kind, count in sorted(kind_totals.items()):
        if kind not in ("security", "performance", "maintainability", "reliability", "unknown"):
            parts.append(f"{count} {kind} issue{'s' if count > 1 else ''}")

    issue_str = (": " + ", ".join(parts)) if parts else ""

    # Entity names (up to 3)
    if n <= 3:
        name_str = " [" + ", ".join(f"'{nm}'" for nm in names) + "]"
    else:
        name_str = " ['" + "', '".join(names[:2]) + f"', and {n - 2} more]"

    return f"{lead}{name_str}{issue_str}. Combined pain score: {round(total_pain, 1)}."


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
