from __future__ import annotations

import dataclasses
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


# ---------------------------------------------------------------------------
# Severity enum  (internal; serialized as string in output)
# ---------------------------------------------------------------------------

class Severity(IntEnum):
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return {
            "low":      cls.LOW,
            "medium":   cls.MEDIUM,
            "high":     cls.HIGH,
            "critical": cls.CRITICAL,
        }.get(s.lower(), cls.LOW)


# ---------------------------------------------------------------------------
# Leaf models
# ---------------------------------------------------------------------------

@dataclass
class RepositoryInfo:
    name: str = ""
    language: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    commit_hash: str = ""
    branch: str = ""
    file_count: int = 0


@dataclass
class ArchitectureInfo:
    detected_pattern: str = "unknown"
    services: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class MetricsInfo:
    total_functions: int = 0
    avg_function_length: float = 0.0
    high_complexity_functions: int = 0
    test_coverage_estimate: float = 0.0
    todo_count: int = 0


@dataclass
class OutdatedPackage:
    name: str = ""
    current: str = ""
    recommended: str = ""


@dataclass
class UnusedDependency:
    """Unused dependency with a deterministic confidence score."""
    name: str = ""
    confidence: float = 1.0   # 0.0–1.0 (1.0 = certainly unused)
    reasons: list[str] = field(default_factory=list)


@dataclass
class DependenciesInfo:
    outdated_packages: list[OutdatedPackage] = field(default_factory=list)
    unused_dependencies: list[UnusedDependency] = field(default_factory=list)


@dataclass
class AuditContext:
    """Structural context for an audited entity."""
    imports: list[str] = field(default_factory=list)   # modules imported by this entity's file
    callers: list[str] = field(default_factory=list)   # files that import this entity's file
    callees: list[str] = field(default_factory=list)   # files this entity's file imports


@dataclass
class Evidence:
    type: str = ""
    value: Any = None
    threshold: Any = None


@dataclass
class Finding:
    id: str = ""
    type: str = ""
    severity: str = "low"
    title: str = ""
    file: str = ""
    symbol: str = ""
    line: int = 0
    end_line: int = 0          # inclusive end line (0 = unknown / single-line)
    snippet: str = ""          # dedented, line-numbered code window around the finding
    evidence: list[Evidence] = field(default_factory=list)
    entity_id: str = ""
    related_findings: list[str] = field(default_factory=list)
    confidence: float = 0.8
    context: AuditContext = field(default_factory=AuditContext)
    kind: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class CodeSmell:
    id: str = ""
    type: str = ""
    severity: str = "low"
    title: str = ""
    file: str = ""
    symbol: str = ""
    line: int = 0
    end_line: int = 0          # inclusive end line (0 = unknown / single-line)
    snippet: str = ""          # dedented, line-numbered code window around the finding
    evidence: list[Evidence] = field(default_factory=list)
    entity_id: str = ""
    related_findings: list[str] = field(default_factory=list)
    confidence: float = 0.8
    context: AuditContext = field(default_factory=AuditContext)
    kind: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class ChangeSet:
    changed_files: list[str] = field(default_factory=list)
    added_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)


@dataclass
class EvidenceEntry:
    file: str = ""
    line: int = 0
    description: str = ""


# ---------------------------------------------------------------------------
# Audit context / object model
# ---------------------------------------------------------------------------

@dataclass
class AuditObject:
    """Central, referenceable entity identified during an audit run."""
    entity_id: str = ""
    kind: str = ""          # function | class | file | service | package
    name: str = ""
    file: str = ""
    confidence: float = 0.0
    context: AuditContext = field(default_factory=AuditContext)


# ---------------------------------------------------------------------------
# Relationships / graph model
# ---------------------------------------------------------------------------

@dataclass
class ImportEdge:
    """A directed dependency between two source files."""
    source: str = ""
    target: str = ""
    type: str = "imports"
    confidence: float = 1.0


@dataclass
class RelationshipsInfo:
    """
    Derived from the internal import graph built across all analyzers.

    - nodes: every source file that participates in at least one edge, sorted
    - edges: directed import relationships, sorted source → target
    - cycles: circular import chains (each cycle sorted internally then globally)
    - coupling_score: directed graph density [0.0, 1.0]
    """
    nodes: list[str] = field(default_factory=list)
    edges: list[ImportEdge] = field(default_factory=list)
    cycles: list[list[str]] = field(default_factory=list)
    coupling_score: float = 0.0


# ---------------------------------------------------------------------------
# Hotspot map
# ---------------------------------------------------------------------------

@dataclass
class HotspotEntry:
    """A file or entity that concentrates many issues — used by the context compressor."""
    entity_id: str = ""
    entity_kind: str = ""       # file | function | class
    file: str = ""
    overall_severity: str = "low"   # worst severity across all issues
    issue_counts: dict[str, int] = field(default_factory=dict)   # kind → count
    top_findings: list[dict] = field(default_factory=list)       # lightweight summaries
    related_entities: list[str] = field(default_factory=list)    # callers/callees
    total_weight: float = 0.0   # composite risk score


# ---------------------------------------------------------------------------
# Root result
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    repository: RepositoryInfo = field(default_factory=RepositoryInfo)
    architecture: ArchitectureInfo = field(default_factory=ArchitectureInfo)
    metrics: MetricsInfo = field(default_factory=MetricsInfo)
    dependencies: DependenciesInfo = field(default_factory=DependenciesInfo)
    findings: list[Finding] = field(default_factory=list)
    code_smells: list[CodeSmell] = field(default_factory=list)
    relationships: RelationshipsInfo = field(default_factory=RelationshipsInfo)
    evidence_index: dict[str, EvidenceEntry] = field(default_factory=dict)
    audit_objects: list[AuditObject] = field(default_factory=list)
    hotspots: list[HotspotEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        """
        Return a JSON-serialisable dict with canonical (deterministic) ordering.

        Key transformations applied here (not in analyzers):
          - findings grouped by (file, symbol) with numeric severity/confidence
          - security findings sorted and counted
          - relationships sorted deterministically
          - unused dependencies with confidence + reasons
          - hotspots computed from all findings + smells
        """
        from .scoring import severity_numeric, confidence_numeric

        # ----------------------------------------------------------------
        # Severity helpers (used in hotspot computation below)
        # ----------------------------------------------------------------
        from .scoring import _SEVERITY_NUMERIC
        _SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}

        # ----------------------------------------------------------------
        # Base serialization
        # ----------------------------------------------------------------
        raw: dict = dataclasses.asdict(self)

        # ---- repository ------------------------------------------------
        raw["repository"]["language"] = sorted(raw["repository"]["language"])
        raw["repository"]["frameworks"] = sorted(raw["repository"]["frameworks"])

        # ---- findings: group by (file, symbol), compute numeric scores --
        # security findings (kind="security") are emitted in the separate security section
        groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for f in self.findings:
            if f.kind == "security":
                continue
            primary_val = 0.0
            for ev in f.evidence:
                primary_val = max(primary_val, ev.value or 0)
            sev_num = severity_numeric(f.severity, f.type, primary_val)
            conf    = confidence_numeric(f.type, len(f.evidence))
            issue = {
                "id":               f.id,
                "type":             f.type,
                "kind":             f.kind,
                "severity":         sev_num,
                "confidence":       conf,
                "line":             f.line,
                "end_line":         f.end_line,
                "snippet":          f.snippet,
                "evidence":         [dataclasses.asdict(e) for e in f.evidence],
                "entity_id":        f.entity_id,
                "related_findings": f.related_findings,
                "tags":             f.tags,
                "context":          dataclasses.asdict(f.context),
            }
            groups[(f.file, f.symbol)].append(issue)

        grouped_findings: list[dict] = []
        for (file, symbol), issues in sorted(groups.items()):
            # Within group: highest severity first, then type alpha
            issues_sorted = sorted(
                issues,
                key=lambda x: (-x["severity"], x["type"]),
            )
            grouped_findings.append({
                "file":   file,
                "symbol": symbol,
                "issues": issues_sorted,
            })

        raw["findings"] = grouped_findings

        # ---- code_smells (kept flat, numeric scores added) ---------------
        smells_out = []
        for s in self.code_smells:
            primary_val = 0.0
            for ev in s.evidence:
                primary_val = max(primary_val, ev.value or 0)
            sev_num = severity_numeric(s.severity, s.type, primary_val)
            conf    = confidence_numeric(s.type, len(s.evidence))
            smell_d = dataclasses.asdict(s)
            smell_d["severity"] = sev_num
            smell_d["confidence"] = conf
            smells_out.append(smell_d)
        raw["code_smells"] = sorted(
            smells_out, key=lambda s: (s["file"], s["line"], s["type"])
        )

        # ---- security --------------------------------------------------
        # Security findings are stored as Finding(kind="security") in self.findings
        sec_findings_list = [f for f in self.findings if f.kind == "security"]
        sec_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        sec_findings_out = []
        for sf in sec_findings_list:
            sev_str = sf.severity.lower()
            if sev_str in sec_counts:
                sec_counts[sev_str] += 1
            sev_num = _SEVERITY_NUMERIC.get(sev_str, 5.0)
            sec_findings_out.append({
                "type":             sf.type,
                "file":             sf.file,
                "line":             sf.line,
                "end_line":         sf.end_line,
                "snippet":          sf.snippet,
                "severity":         sf.severity,
                "severity_numeric": sev_num,
                "title":            sf.title,
                "confidence":       sf.confidence,
                "entity_id":        sf.entity_id,
                "related_findings": sf.related_findings,
                "tags":             sf.tags,
            })
        raw["security"] = {
            "critical_count": sec_counts["critical"],
            "high_count":     sec_counts["high"],
            "medium_count":   sec_counts["medium"],
            "low_count":      sec_counts["low"],
            "findings": sorted(
                sec_findings_out,
                key=lambda s: (-s["severity_numeric"], s["file"], s["line"]),
            ),
        }

        # ---- dependencies: unused with confidence -----------------------
        raw["dependencies"]["unused_dependencies"] = sorted(
            raw["dependencies"]["unused_dependencies"],
            key=lambda u: u["name"],
        )
        raw["dependencies"]["outdated_packages"] = sorted(
            raw["dependencies"]["outdated_packages"],
            key=lambda p: p["name"],
        )

        # ---- relationships: deterministic sort -------------------------
        raw["relationships"]["nodes"] = sorted(raw["relationships"]["nodes"])
        raw["relationships"]["edges"] = sorted(
            raw["relationships"]["edges"],
            key=lambda e: (e["source"], e["target"]),
        )
        raw["relationships"]["cycles"] = sorted(
            [sorted(c) for c in raw["relationships"]["cycles"]]
        )
        raw["relationships"]["coupling_score"] = round(
            raw["relationships"]["coupling_score"], 4
        )

        # ---- evidence_index --------------------------------------------
        raw["evidence_index"] = dict(sorted(raw["evidence_index"].items()))

        # ---- audit_objects: sorted deterministically -------------------
        raw["audit_objects"] = sorted(
            raw["audit_objects"],
            key=lambda ao: (ao["file"], ao["kind"], ao["name"]),
        )

        # ---- hotspots --------------------------------------------------
        # Build AuditObject lookup for related_entities resolution
        ao_by_eid: dict[str, AuditObject] = {ao.entity_id: ao for ao in self.audit_objects}
        ao_by_file: dict[str, AuditObject] = {ao.file: ao for ao in self.audit_objects
                                               if ao.kind == "file"}

        # Gather all issues (findings + smells) keyed by entity_id
        from collections import defaultdict as _dd
        hs_issues: dict[str, list[dict]] = _dd(list)

        for f in self.findings:
            eid = f.entity_id or f.file  # fallback to file-level bucket
            hs_issues[eid].append({
                "id":       f.id,
                "title":    f.title,
                "severity": f.severity,
                "kind":     f.kind,
                "line":     f.line,
                "file":     f.file,
                "entity_id": f.entity_id,
            })

        for s in self.code_smells:
            eid = s.entity_id or s.file
            hs_issues[eid].append({
                "id":       s.id,
                "title":    s.title,
                "severity": s.severity,
                "kind":     s.kind,
                "line":     s.line,
                "file":     s.file,
                "entity_id": s.entity_id,
            })

        # Severity weight map for total_weight scoring
        _SEV_WEIGHT = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0}

        hotspots_out: list[dict] = []
        for eid, issues in hs_issues.items():
            # Determine entity metadata from audit_objects or derive from file
            ao = ao_by_eid.get(eid) or ao_by_file.get(eid)
            entity_kind = ao.kind if ao else "file"
            entity_file = ao.file if ao else (issues[0]["file"] if issues else "")

            # Count issues by kind
            issue_counts: dict[str, int] = {}
            for iss in issues:
                k = iss["kind"] or "unknown"
                issue_counts[k] = issue_counts.get(k, 0) + 1

            # Overall severity = worst individual severity
            worst_sev = max(
                (_SEV_ORDER.get(iss["severity"].lower(), 0) for iss in issues),
                default=0,
            )
            overall_sev = {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(worst_sev, "low")

            # Total weight
            total_weight = sum(
                _SEV_WEIGHT.get(iss["severity"].lower(), 1.0) for iss in issues
            )

            # Top findings (up to 5, worst severity first)
            top = sorted(issues, key=lambda x: (-_SEV_ORDER.get(x["severity"].lower(), 0), x["line"]))[:5]
            top_findings = [
                {"id": t["id"], "title": t["title"], "severity": t["severity"], "line": t["line"]}
                for t in top
            ]

            # Related entities from audit_object context
            related: list[str] = []
            if ao:
                related = sorted(set(ao.context.callers + ao.context.callees))

            hotspots_out.append({
                "entity_id":       eid,
                "entity_kind":     entity_kind,
                "file":            entity_file,
                "overall_severity": overall_sev,
                "issue_counts":    issue_counts,
                "top_findings":    top_findings,
                "related_entities": related,
                "total_weight":    round(total_weight, 2),
            })

        # Sort by total_weight descending, then entity_id for determinism
        hotspots_out.sort(key=lambda h: (-h["total_weight"], h["entity_id"]))
        raw["hotspots"] = hotspots_out

        return raw

