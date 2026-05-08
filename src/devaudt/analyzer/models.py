from __future__ import annotations

import dataclasses
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


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
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class SecurityFinding:
    type: str = ""
    file: str = ""
    line: int = 0
    severity: str = "medium"
    description: str = ""


@dataclass
class SecurityInfo:
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings: list[SecurityFinding] = field(default_factory=list)


@dataclass
class CodeSmell:
    id: str = ""
    type: str = ""
    severity: str = "low"
    title: str = ""
    file: str = ""
    symbol: str = ""
    line: int = 0
    evidence: list[Evidence] = field(default_factory=list)


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
# Root result
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    repository: RepositoryInfo = field(default_factory=RepositoryInfo)
    architecture: ArchitectureInfo = field(default_factory=ArchitectureInfo)
    metrics: MetricsInfo = field(default_factory=MetricsInfo)
    dependencies: DependenciesInfo = field(default_factory=DependenciesInfo)
    findings: list[Finding] = field(default_factory=list)
    security: SecurityInfo = field(default_factory=SecurityInfo)
    code_smells: list[CodeSmell] = field(default_factory=list)
    change_set: ChangeSet = field(default_factory=ChangeSet)
    relationships: RelationshipsInfo = field(default_factory=RelationshipsInfo)
    evidence_index: dict[str, EvidenceEntry] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """
        Return a JSON-serialisable dict with canonical (deterministic) ordering.

        Key transformations applied here (not in analyzers):
          - findings grouped by (file, symbol) with numeric severity/confidence
          - security findings sorted and counted
          - relationships sorted deterministically
          - unused dependencies with confidence + reasons
        """
        from .scoring import severity_numeric, confidence_numeric

        # ----------------------------------------------------------------
        # Base serialization
        # ----------------------------------------------------------------
        raw: dict = dataclasses.asdict(self)

        # ---- repository ------------------------------------------------
        raw["repository"]["language"] = sorted(raw["repository"]["language"])
        raw["repository"]["frameworks"] = sorted(raw["repository"]["frameworks"])

        # ---- findings: group by (file, symbol), compute numeric scores --
        groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for f in self.findings:
            primary_val = 0.0
            for ev in f.evidence:
                primary_val = max(primary_val, ev.value or 0)
            sev_num = severity_numeric(f.severity, f.type, primary_val)
            conf    = confidence_numeric(f.type, len(f.evidence))
            issue = {
                "id":          f.id,
                "type":        f.type,
                "severity":    sev_num,
                "confidence":  conf,
                "line":        f.line,
                "evidence":    [dataclasses.asdict(e) for e in f.evidence],
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
        sec_findings_out = []
        for sf in self.security.findings:
            from .scoring import _SEVERITY_NUMERIC
            sf_d = dataclasses.asdict(sf)
            sf_d["severity_numeric"] = _SEVERITY_NUMERIC.get(sf.severity.lower(), 5.0)
            sec_findings_out.append(sf_d)
        raw["security"]["findings"] = sorted(
            sec_findings_out,
            key=lambda s: (-s["severity_numeric"], s["file"], s["line"]),
        )

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

        # ---- change_set ------------------------------------------------
        raw["change_set"]["changed_files"] = sorted(raw["change_set"]["changed_files"])
        raw["change_set"]["added_files"]   = sorted(raw["change_set"]["added_files"])
        raw["change_set"]["deleted_files"] = sorted(raw["change_set"]["deleted_files"])

        # ---- evidence_index --------------------------------------------
        raw["evidence_index"] = dict(sorted(raw["evidence_index"].items()))

        return raw
