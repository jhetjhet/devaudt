"""
analyzer/risk.py — Standalone Risk Scoring Engine.

Consumes a fully-populated ``AnalysisResult`` and produces a ``RiskReport``
containing a ``WeightedRiskProfile`` for every entity (file, function, class)
found across findings and code-smells.

Pain Score (0–100)
------------------
A composite, confidence-weighted metric that answers:
    "Where will human or LLM attention yield the highest ROI?"

Components (all normalised 0–1 before weighting):

  severity_burden    — weighted sum of per-issue severity values
  issue_density      — issue count relative to the busiest entity
  complexity_pressure — high-complexity function count from MetricsInfo (repo-level proxy)
  smell_pressure     — proportion of smells attributed to this entity
  confidence_score   — mean confidence across the entity's issues
  hotspot_factor     — whether a pre-computed HotspotEntry exists + its weight

Final score: dot-product with WEIGHTS, scaled to [0, 100] and rounded to 1 d.p.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .models import AnalysisResult, Finding, CodeSmell, Severity
from .scoring import _SEVERITY_NUMERIC

# ---------------------------------------------------------------------------
# Tuneable weights (must sum to 1.0)
# ---------------------------------------------------------------------------

WEIGHTS: dict[str, float] = {
    "severity_burden":     0.35,
    "issue_density":       0.20,
    "complexity_pressure": 0.10,
    "smell_pressure":      0.15,
    "confidence_score":    0.10,
    "hotspot_factor":      0.10,
}

assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9, "WEIGHTS must sum to 1.0"

# Severity → numeric weight for burden calculation (same scale as _SEVERITY_NUMERIC)
_SEV_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high":      7.5,
    "medium":    5.0,
    "low":       2.5,
    "info":      1.0,
}

# Maximum credible burden per entity before we cap/saturate (tuning knob)
_BURDEN_SATURATION = 60.0


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------

@dataclass
class WeightedRiskProfile:
    """Risk profile for a single entity (file, function, or class)."""

    entity_id: str = ""
    entity_kind: str = "file"          # file | function | class | service
    file: str = ""
    name: str = ""                      # human-readable name (function/class name, or file path)
    rank: int = 0                       # 1 = riskiest; assigned after sorting

    # Raw component scores (0.0–1.0)
    severity_burden: float = 0.0
    issue_density: float = 0.0
    complexity_pressure: float = 0.0
    smell_pressure: float = 0.0
    confidence_score: float = 0.0
    hotspot_factor: float = 0.0

    # Final composite (0.0–100.0)
    pain_score: float = 0.0

    # Human-readable context
    issue_count: int = 0
    smell_count: int = 0
    top_issues: list[dict[str, Any]] = field(default_factory=list)
    issue_kinds: dict[str, int] = field(default_factory=dict)   # kind → count
    explanation: str = ""

    # Structural context (from AuditContext) — used by the correlation layer
    callers: list[str] = field(default_factory=list)   # files that import this entity's file
    callees: list[str] = field(default_factory=list)   # files this entity's file imports

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id":           self.entity_id,
            "entity_kind":         self.entity_kind,
            "file":                self.file,
            "name":                self.name,
            "rank":                self.rank,
            "pain_score":          self.pain_score,
            "components": {
                "severity_burden":     round(self.severity_burden, 4),
                "issue_density":       round(self.issue_density, 4),
                "complexity_pressure": round(self.complexity_pressure, 4),
                "smell_pressure":      round(self.smell_pressure, 4),
                "confidence_score":    round(self.confidence_score, 4),
                "hotspot_factor":      round(self.hotspot_factor, 4),
            },
            "issue_count":  self.issue_count,
            "smell_count":  self.smell_count,
            "issue_kinds":  self.issue_kinds,
            "top_issues":   self.top_issues,
            "explanation":  self.explanation,
            "callers":      self.callers,
            "callees":      self.callees,
        }


@dataclass
class RiskReport:
    """Repository-level risk report produced by RiskScoringEngine."""

    profiles: list[WeightedRiskProfile] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    generated_at: str = ""
    total_entities: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at":   self.generated_at,
            "total_entities": self.total_entities,
            "summary":        self.summary,
            "profiles":       [p.to_dict() for p in self.profiles],
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class RiskScoringEngine:
    """
    Transforms an ``AnalysisResult`` into a ``RiskReport``.

    Usage::

        from devaudt.analyzer.risk import RiskScoringEngine
        report = RiskScoringEngine().score(result)
        print(report.to_dict())
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, result: AnalysisResult) -> RiskReport:
        """Return a fully populated ``RiskReport`` for *result*."""

        # Group issues by entity_id (fall back to file path)
        findings_by_entity: dict[str, list[Finding]] = defaultdict(list)
        smells_by_entity:   dict[str, list[CodeSmell]] = defaultdict(list)

        for f in result.findings:
            key = f.entity_id or f.file or "__unknown__"
            findings_by_entity[key].append(f)

        for s in result.code_smells:
            key = s.entity_id or s.file or "__unknown__"
            smells_by_entity[key].append(s)

        all_keys = set(findings_by_entity) | set(smells_by_entity)
        if not all_keys:
            return RiskReport(
                generated_at=_now_iso(),
                total_entities=0,
                summary=self._empty_summary(),
            )

        # Pre-compute repo-wide denominators for normalisation
        max_issue_count = max(
            len(findings_by_entity.get(k, [])) for k in all_keys
        )
        max_smell_count = max(
            len(smells_by_entity.get(k, [])) for k in all_keys
        )
        total_smells = sum(len(v) for v in smells_by_entity.values())

        # Build hotspot lookup: entity_id → total_weight
        hotspot_weight: dict[str, float] = {}
        max_hotspot_weight = 0.0
        for hs in result.hotspots:
            hotspot_weight[hs.entity_id] = hs.total_weight
            if hs.total_weight > max_hotspot_weight:
                max_hotspot_weight = hs.total_weight
        # Also index by file for file-based entities
        for hs in result.hotspots:
            if hs.file and hs.file not in hotspot_weight:
                hotspot_weight[hs.file] = hs.total_weight

        # Complexity pressure: repo-level fraction (same for all file entities;
        # sub-entity kinds inherit from their file's contribution)
        repo_complexity_pressure = self._repo_complexity_pressure(result)

        # Build audit_object lookup for kind resolution
        ao_kind: dict[str, str] = {ao.entity_id: ao.kind for ao in result.audit_objects}
        ao_file: dict[str, str] = {ao.entity_id: ao.file for ao in result.audit_objects}
        ao_name: dict[str, str] = {ao.entity_id: ao.name for ao in result.audit_objects}
        ao_ctx:  dict[str, Any] = {ao.entity_id: ao.context for ao in result.audit_objects}

        profiles: list[WeightedRiskProfile] = []

        for key in all_keys:
            entity_findings = findings_by_entity.get(key, [])
            entity_smells   = smells_by_entity.get(key, [])

            # --- entity metadata ---
            entity_kind = self._resolve_kind(
                key, entity_findings, entity_smells, ao_kind
            )
            entity_file = self._resolve_file(
                key, entity_findings, entity_smells, ao_file
            )
            entity_name = ao_name.get(key) or entity_file or key

            # --- severity burden (normalised) ---
            raw_burden = sum(
                _SEV_WEIGHT.get(i.severity.lower(), 2.5) * i.confidence
                for i in entity_findings
            ) + sum(
                _SEV_WEIGHT.get(s.severity.lower(), 2.5) * s.confidence * 0.6
                for s in entity_smells
            )
            sev_burden = min(raw_burden / _BURDEN_SATURATION, 1.0)

            # --- issue density (normalised) ---
            issue_density = (
                len(entity_findings) / max(max_issue_count, 1)
            )

            # --- smell pressure (normalised) ---
            smell_pressure = (
                len(entity_smells) / max(max_smell_count, 1)
                if max_smell_count
                else 0.0
            )

            # --- confidence score: mean confidence across all issues ---
            all_issues = [*entity_findings, *entity_smells]
            confidence_score = (
                sum(i.confidence for i in all_issues) / len(all_issues)
                if all_issues else 0.0
            )

            # --- hotspot factor (normalised) ---
            hw = hotspot_weight.get(key) or hotspot_weight.get(entity_file, 0.0)
            hotspot_factor = (
                min(hw / max(max_hotspot_weight, 1.0), 1.0)
                if max_hotspot_weight else 0.0
            )

            # --- pain score ---
            pain_score = round(
                (
                    WEIGHTS["severity_burden"]     * sev_burden
                    + WEIGHTS["issue_density"]       * issue_density
                    + WEIGHTS["complexity_pressure"] * repo_complexity_pressure
                    + WEIGHTS["smell_pressure"]      * smell_pressure
                    + WEIGHTS["confidence_score"]    * confidence_score
                    + WEIGHTS["hotspot_factor"]      * hotspot_factor
                ) * 100,
                1,
            )

            # --- top issues (up to 5, highest severity first) ---
            sorted_findings = sorted(
                entity_findings,
                key=lambda f: (
                    _SEV_WEIGHT.get(f.severity.lower(), 2.5),
                    f.confidence,
                ),
                reverse=True,
            )
            top_issues = [
                {
                    "id":       f.id,
                    "title":    f.title,
                    "severity": f.severity,
                    "kind":     f.kind,
                    "line":     f.line,
                    "confidence": round(f.confidence, 2),
                }
                for f in sorted_findings[:5]
            ]

            # --- issue kind breakdown ---
            issue_kinds: dict[str, int] = defaultdict(int)
            for f in entity_findings:
                issue_kinds[f.kind or "unknown"] += 1
            for s in entity_smells:
                issue_kinds[s.kind or "unknown"] += 1

            # --- explanation ---
            explanation = self._build_explanation(
                entity_id=key,
                entity_name=entity_name,
                entity_kind=entity_kind,
                sev_burden=sev_burden,
                issue_density=issue_density,
                smell_pressure=smell_pressure,
                hotspot_factor=hotspot_factor,
                pain_score=pain_score,
                issue_count=len(entity_findings),
            )

            # --- caller / callee context from AuditObject ---
            ctx = ao_ctx.get(key)
            entity_callers: list[str] = list(ctx.callers) if ctx else []
            entity_callees: list[str] = list(ctx.callees) if ctx else []
            # Fallback: pull from any finding's embedded context
            if not entity_callers and not entity_callees:
                for item in [*entity_findings, *entity_smells]:
                    if item.context.callers or item.context.callees:
                        entity_callers = list(item.context.callers)
                        entity_callees = list(item.context.callees)
                        break

            profiles.append(
                WeightedRiskProfile(
                    entity_id=key,
                    entity_kind=entity_kind,
                    file=entity_file,
                    name=entity_name,
                    severity_burden=sev_burden,
                    issue_density=issue_density,
                    complexity_pressure=repo_complexity_pressure,
                    smell_pressure=smell_pressure,
                    confidence_score=confidence_score,
                    hotspot_factor=hotspot_factor,
                    pain_score=pain_score,
                    issue_count=len(entity_findings),
                    smell_count=len(entity_smells),
                    top_issues=top_issues,
                    issue_kinds=dict(issue_kinds),
                    explanation=explanation,
                    callers=entity_callers,
                    callees=entity_callees,
                )
            )

        # Sort by pain_score desc, entity_id asc for stability
        profiles.sort(key=lambda p: (-p.pain_score, p.entity_id))
        for i, p in enumerate(profiles, start=1):
            p.rank = i

        summary = self._build_summary(profiles, result)

        return RiskReport(
            profiles=profiles,
            summary=summary,
            generated_at=_now_iso(),
            total_entities=len(profiles),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _repo_complexity_pressure(result: AnalysisResult) -> float:
        """
        Normalised complexity pressure at the repository level.

        Uses ``MetricsInfo.high_complexity_functions`` relative to
        ``total_functions``.  Returns 0.0 when no function data is available.
        """
        total = result.metrics.total_functions
        if total <= 0:
            return 0.0
        ratio = result.metrics.high_complexity_functions / total
        # Apply a mild log-stretch so a few complex functions still register
        return round(min(math.log1p(ratio * 10) / math.log1p(10), 1.0), 4)

    @staticmethod
    def _resolve_kind(
        key: str,
        findings: list[Finding],
        smells: list[CodeSmell],
        ao_kind: dict[str, str],
    ) -> str:
        if key in ao_kind:
            return ao_kind[key]
        # Infer from first available issue
        for item in [*findings, *smells]:
            if item.kind:
                pass  # kind here is issue kind, not entity kind
        # If the key looks like a file path, call it a file
        if "." in key.split("/")[-1] or "/" in key:
            return "file"
        return "function"

    @staticmethod
    def _resolve_file(
        key: str,
        findings: list[Finding],
        smells: list[CodeSmell],
        ao_file: dict[str, str],
    ) -> str:
        if key in ao_file:
            return ao_file[key]
        for item in [*findings, *smells]:
            if item.file:
                return item.file
        return key

    @staticmethod
    def _build_explanation(
        *,
        entity_id: str,
        entity_name: str,
        entity_kind: str,
        sev_burden: float,
        issue_density: float,
        smell_pressure: float,
        hotspot_factor: float,
        pain_score: float,
        issue_count: int,
    ) -> str:
        parts: list[str] = []

        label = entity_name or entity_id
        if pain_score >= 75:
            parts.append(f"Critical attention required: {entity_kind} '{label}'")
        elif pain_score >= 50:
            parts.append(f"High-priority {entity_kind}: '{label}'")
        elif pain_score >= 25:
            parts.append(f"Moderate risk in {entity_kind} '{label}'")
        else:
            parts.append(f"Low-risk {entity_kind} '{label}'")

        if sev_burden > 0.7:
            parts.append("carries severe-weighted issues")
        elif sev_burden > 0.4:
            parts.append("has moderate severity burden")

        if issue_count:
            parts.append(f"{issue_count} finding(s)")

        if smell_pressure > 0.5:
            parts.append("high smell density")

        if hotspot_factor > 0.5:
            parts.append("flagged as structural hotspot")

        return "; ".join(parts) + "."

    @staticmethod
    def _build_summary(
        profiles: list[WeightedRiskProfile],
        result: AnalysisResult,
    ) -> dict[str, Any]:
        if not profiles:
            return RiskScoringEngine._empty_summary()

        scores = [p.pain_score for p in profiles]
        top5 = [
            {"rank": p.rank, "entity_id": p.entity_id, "pain_score": p.pain_score}
            for p in profiles[:5]
        ]

        # Worst file (pain_score of file-kind entities)
        file_profiles = [p for p in profiles if p.entity_kind == "file"]
        worst_file = file_profiles[0].file if file_profiles else profiles[0].file

        # Kind distribution across all issues
        kind_totals: dict[str, int] = defaultdict(int)
        for p in profiles:
            for k, c in p.issue_kinds.items():
                kind_totals[k] += c

        critical_entities = sum(1 for p in profiles if p.pain_score >= 75)
        high_risk_entities = sum(1 for p in profiles if 50 <= p.pain_score < 75)

        return {
            "top_risky_entities":  top5,
            "worst_file":          worst_file,
            "average_pain":        round(sum(scores) / len(scores), 1),
            "max_pain":            max(scores),
            "critical_entities":   critical_entities,
            "high_risk_entities":  high_risk_entities,
            "issue_kind_totals":   dict(kind_totals),
            "total_findings":      len(result.findings),
            "total_smells":        len(result.code_smells),
        }

    @staticmethod
    def _empty_summary() -> dict[str, Any]:
        return {
            "top_risky_entities": [],
            "worst_file": "",
            "average_pain": 0.0,
            "max_pain": 0.0,
            "critical_entities": 0,
            "high_risk_entities": 0,
            "issue_kind_totals": {},
            "total_findings": 0,
            "total_smells": 0,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
