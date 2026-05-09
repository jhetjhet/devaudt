"""
analyzer/context.py — Context Compressor (Layer 4).

Consumes ``AnalysisResult`` (L1), ``RiskReport`` (L2), and ``CorrelationReport``
(L3) to produce a compact ``ContextPacket`` — a narrative-driven, token-budgeted
prompt ready for submission to an LLM.

Layer 4 pipeline
----------------
1. Prioritize  — Select only hotspot clusters from L3 (top N by pain, default 3).
2. Resolve     — Join each hotspot's members back to L2 risk profiles and L1
                  raw evidence (snippets, finding titles, line numbers).
3. Budget      — Estimate token usage.  If over budget, trim evidence in
                  priority order: code-smell detail first, then non-security
                  snippets, then security snippets (shortened).
4. Format      — Render a structured Markdown reasoning prompt with
                  cluster-level narratives, entity-level risk context, and
                  annotated code snippets that emphasise call-chain relationships.

Output: ``ContextPacket``
--------------------------
A minimal object containing:
  • ``formatted_prompt``    — The complete LLM-ready reasoning prompt (Markdown).
  • ``token_estimate``      — Approximate token count (heuristic: 4 chars ≈ 1 token).
  • ``included_clusters``   — Cluster IDs that made the cut.
  • ``truncated_entities``  — Entity IDs whose evidence was partially trimmed.
  • ``metadata``            — Repo name, branch, frameworks, analysis date, …
"""
from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .correlation import ClusterProfile, CorrelationReport
from .models import AnalysisResult, CodeSmell, Finding
from .risk import RiskReport, WeightedRiskProfile

# ---------------------------------------------------------------------------
# Tuneable constants
# ---------------------------------------------------------------------------

# How many hotspot clusters to keep by default
TOP_N_CLUSTERS: int = 3

# Rough token budget for the finished prompt (~8 k for GPT-4 / Claude)
DEFAULT_TOKEN_BUDGET: int = 8_000

# Snippet line limits at each fidelity level
SNIPPET_FULL_LINES: int = 20    # normal rendering
SNIPPET_TRIM_LINES: int = 7     # applied under budget pressure

# Max code smells shown per entity at each fidelity level
MAX_SMELLS_FULL: int = 5
MAX_SMELLS_TRIM: int = 2

# Heuristic: average characters per LLM token (GPT-4 / Claude ~ 4)
_CHARS_PER_TOKEN: int = 4


# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------

@dataclass
class ContextPacket:
    """
    The output of the Context Compressor layer.

    ``formatted_prompt`` is the primary field — a complete, LLM-ready Markdown
    string.  All other fields are lightweight metadata for LLM orchestration.
    """

    formatted_prompt: str = ""
    token_estimate: int = 0
    included_clusters: list[str] = field(default_factory=list)   # cluster_ids
    truncated_entities: list[str] = field(default_factory=list)  # entity_ids
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_estimate":     self.token_estimate,
            "included_clusters":  self.included_clusters,
            "truncated_entities": self.truncated_entities,
            "metadata":           self.metadata,
            "formatted_prompt":   self.formatted_prompt,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ContextCompressor:
    """
    Transforms upstream pipeline outputs into a compact, LLM-ready ``ContextPacket``.

    Usage::

        from devaudt.analyzer.context import ContextCompressor
        packet = ContextCompressor().compress(result, risk_report, correlation_report)
        print(packet.formatted_prompt)
    """

    def compress(
        self,
        result: AnalysisResult,
        risk_report: RiskReport,
        correlation_report: CorrelationReport,
        top_n: int = TOP_N_CLUSTERS,
        token_budget: int = DEFAULT_TOKEN_BUDGET,
    ) -> ContextPacket:
        """Return a ``ContextPacket`` for the given pipeline outputs."""

        # ----------------------------------------------------------------
        # Step 1 — Prioritize: select top-N hotspot clusters
        # ----------------------------------------------------------------
        hotspots = [c for c in correlation_report.clusters if c.is_hotspot]
        selected: list[ClusterProfile] = list(hotspots[:top_n])

        # Fallback: pad with highest-pain non-hotspots when fewer than top_n exist
        if len(selected) < top_n:
            non_hotspot = [c for c in correlation_report.clusters if not c.is_hotspot]
            selected += non_hotspot[: top_n - len(selected)]

        if not selected:
            prompt = _empty_prompt(result)
            return ContextPacket(
                formatted_prompt=prompt,
                token_estimate=_estimate_tokens(prompt),
                metadata=_build_metadata(result, correlation_report),
            )

        included_cluster_ids = [c.cluster_id for c in selected]

        # ----------------------------------------------------------------
        # Step 2 — Resolve: build L1 + L2 lookup tables
        # ----------------------------------------------------------------
        findings_by_entity: dict[str, list[Finding]] = defaultdict(list)
        for f in result.findings:
            key = f.entity_id or f.file or "__unknown__"
            findings_by_entity[key].append(f)

        smells_by_entity: dict[str, list[CodeSmell]] = defaultdict(list)
        for s in result.code_smells:
            key = s.entity_id or s.file or "__unknown__"
            smells_by_entity[key].append(s)

        profile_by_entity: dict[str, WeightedRiskProfile] = {
            p.entity_id: p for p in risk_report.profiles
        }

        # ----------------------------------------------------------------
        # Step 3 — Budget pass 1: render at full fidelity
        # ----------------------------------------------------------------
        truncated_entities: list[str] = []

        def _render_all(
            snippet_lines: int,
            max_smells: int,
            security_only_snippets: bool = False,
        ) -> str:
            header = _render_header(result, risk_report, len(selected))
            cluster_blocks = [
                _render_cluster(
                    cluster=c,
                    findings_by_entity=findings_by_entity,
                    smells_by_entity=smells_by_entity,
                    profile_by_entity=profile_by_entity,
                    snippet_lines=snippet_lines,
                    max_smells=max_smells,
                    security_only_snippets=security_only_snippets,
                )
                for c in selected
            ]
            return header + "\n\n---\n\n" + "\n\n---\n\n".join(cluster_blocks)

        full_prompt = _render_all(SNIPPET_FULL_LINES, MAX_SMELLS_FULL)
        estimated = _estimate_tokens(full_prompt)

        # ----------------------------------------------------------------
        # Step 3 — Budget pass 2a: trim snippets + reduce smell count
        # ----------------------------------------------------------------
        if estimated > token_budget:
            full_prompt = _render_all(SNIPPET_TRIM_LINES, MAX_SMELLS_TRIM)
            estimated = _estimate_tokens(full_prompt)

        # ----------------------------------------------------------------
        # Step 3 — Budget pass 2b: drop smell snippets; security-only snippets
        # ----------------------------------------------------------------
        if estimated > token_budget:
            full_prompt = _render_all(
                SNIPPET_TRIM_LINES, max_smells=0, security_only_snippets=True
            )
            estimated = _estimate_tokens(full_prompt)

            # Record entities that lost smell detail
            for c in selected:
                for eid in c.members:
                    p = profile_by_entity.get(eid)
                    if p and p.smell_count > 0 and eid not in truncated_entities:
                        truncated_entities.append(eid)

        # ----------------------------------------------------------------
        # Step 4 — Assemble metadata
        # ----------------------------------------------------------------
        metadata = _build_metadata(result, correlation_report)
        metadata["budget_used_pct"] = round(estimated / token_budget * 100, 1)

        return ContextPacket(
            formatted_prompt=full_prompt,
            token_estimate=estimated,
            included_clusters=included_cluster_ids,
            truncated_entities=truncated_entities,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _render_header(
    result: AnalysisResult,
    risk_report: RiskReport,
    n_selected: int,
) -> str:
    """Render the AUDIT CONTEXT header and EXECUTIVE RISK SUMMARY section."""
    repo = result.repository
    arch = result.architecture
    summary = risk_report.summary

    repo_name = repo.name or "Unknown Repository"
    frameworks = ", ".join(repo.frameworks) if repo.frameworks else "N/A"
    detected_pattern = arch.detected_pattern or "unknown"
    languages = ", ".join(repo.language) if repo.language else "N/A"
    branch = repo.branch or "N/A"
    commit = (repo.commit_hash[:8] if repo.commit_hash else "N/A")

    worst_file = summary.get("worst_file", "N/A")
    avg_pain = summary.get("average_pain", 0.0)
    critical_count = summary.get("critical_entities", 0)
    high_count = summary.get("high_risk_entities", 0)
    total_findings = summary.get("total_findings", 0)
    total_smells = summary.get("total_smells", 0)
    kind_totals: dict[str, int] = summary.get("issue_kind_totals", {})
    security_count = kind_totals.get("security", 0)

    # Top-ranked entity explanation from L2
    top_expl = risk_report.profiles[0].explanation if risk_report.profiles else ""

    lines = [
        f"# AUDIT CONTEXT: {repo_name}",
        f"Branch: `{branch}` | Commit: `{commit}` | Language: {languages}",
        f"Framework: {frameworks} | Detected Pattern: {detected_pattern}",
        "",
        "## EXECUTIVE RISK SUMMARY",
        top_expl,
        f"Average Pain Score: {avg_pain} | Worst File: `{worst_file}`",
        f"Critical Entities: {critical_count} | High-Risk Entities: {high_count}",
        (
            f"Total Findings: {total_findings} | "
            f"Total Code Smells: {total_smells} | "
            f"Security Issues: {security_count}"
        ),
        "",
        "---",
        "",
        f"## INVESTIGATION TARGETS ({n_selected} High-Pain Hotspot Cluster{'s' if n_selected != 1 else ''})",
        "The following clusters represent the highest-ROI targets for human or LLM review.",
    ]
    return "\n".join(lines)


def _render_cluster(
    *,
    cluster: ClusterProfile,
    findings_by_entity: dict[str, list[Finding]],
    smells_by_entity: dict[str, list[CodeSmell]],
    profile_by_entity: dict[str, WeightedRiskProfile],
    snippet_lines: int,
    max_smells: int,
    security_only_snippets: bool = False,
) -> str:
    """Render one cluster section with all its member entities."""
    kind_label = {
        "file_hotspot": "File Hotspot",
        "caller_chain": "Caller Chain",
        "mixed":        "Mixed Cluster",
    }.get(cluster.cluster_kind, cluster.cluster_kind.replace("_", " ").title())

    security_flag = "Yes" if cluster.has_security else "No"

    lines = [
        f"### [CLUSTER {cluster.cluster_id}] — {kind_label} (Rank #{cluster.rank})",
        f"**Impact Narrative:** {cluster.narrative}",
        (
            f"**Entities:** {len(cluster.members)} | "
            f"**Total Issues:** {cluster.total_issues} | "
            f"**Security Involved:** {security_flag}"
        ),
        f"**Combined Pain Score:** {cluster.total_pain}",
    ]

    # --- Relationship Summary (aggregate across all cluster members) ---
    member_files_set = set(cluster.member_files)
    external_impacts: set[str] = set()  # files that import this cluster (callers)
    external_deps: set[str] = set()     # files this cluster imports (callees)

    for eid in cluster.members:
        p = profile_by_entity.get(eid)
        if not p:
            continue
        for f in p.callers:
            if f not in member_files_set:
                external_impacts.add(f)
        for f in p.callees:
            if f not in member_files_set:
                external_deps.add(f)

    if external_impacts or external_deps:
        lines.append("**Relationship Summary:**")
        if external_impacts:
            names = sorted(os.path.basename(f) for f in external_impacts)[:5]
            lines.append(f"- Directly impacts: {', '.join(names)}")
        if external_deps:
            names = sorted(os.path.basename(f) for f in external_deps)[:5]
            lines.append(f"- Depends on: {', '.join(names)}")
        lines.append("")

    lines.append("")

    # Members sorted by pain desc
    member_profiles = sorted(
        [profile_by_entity[eid] for eid in cluster.members if eid in profile_by_entity],
        key=lambda p: -p.pain_score,
    )

    for profile in member_profiles:
        entity_block = _render_entity(
            profile=profile,
            findings=findings_by_entity.get(profile.entity_id, []),
            smells=smells_by_entity.get(profile.entity_id, []),
            snippet_lines=snippet_lines,
            max_smells=max_smells,
            security_only_snippets=security_only_snippets,
        )
        lines.append(entity_block)

    return "\n".join(lines)


def _render_entity(
    *,
    profile: WeightedRiskProfile,
    findings: list[Finding],
    smells: list[CodeSmell],
    snippet_lines: int,
    max_smells: int,
    security_only_snippets: bool,
) -> str:
    """Render a single entity evidence block."""
    file_display = profile.file or profile.entity_id
    kind_label = profile.entity_kind.capitalize()

    lines = [
        f"#### Entity: `{file_display}` [{kind_label}] (Pain: {profile.pain_score})",
        f"**Risk Explanation:** {profile.explanation}",
        (
            f"**Risk Components:** "
            f"severity_burden={profile.severity_burden:.2f}, "
            f"issue_density={profile.issue_density:.2f}, "
            f"complexity_pressure={profile.complexity_pressure:.2f}"
        ),
    ]

    # Security findings rendered first, then other findings
    security_findings = sorted(
        [f for f in findings if f.kind == "security"],
        key=lambda f: (_sev_order(f.severity), f.confidence),
        reverse=True,
    )
    other_findings = sorted(
        [f for f in findings if f.kind != "security"],
        key=lambda f: (_sev_order(f.severity), f.confidence),
        reverse=True,
    )
    ordered_findings = security_findings + other_findings

    if ordered_findings:
        lines.append("")
        lines.append("**Key Findings:**")
        for f in ordered_findings:
            line_ref = f" (Line {f.line})" if f.line else ""
            sev_badge = f.severity.upper()
            lines.append(
                f"- [{f.kind or 'finding'}] **{f.title}**{line_ref} — `{sev_badge}`"
            )
            if f.snippet:
                is_security = f.kind == "security"
                if not security_only_snippets or is_security:
                    trimmed = _trim_snippet(f.snippet, snippet_lines)
                    lang = _lang_from_file(f.file)
                    lines.append("")
                    lines.append(f"  ```{lang}")
                    for sl in trimmed.splitlines():
                        lines.append(f"  {sl}")
                    lines.append("  ```")
                    lines.append("")

    # Code smells
    if max_smells > 0 and smells:
        shown = smells[:max_smells]
        lines.append("")
        lines.append(
            f"**Code Smells** ({len(smells)} total, showing {len(shown)}):"
        )
        for s in shown:
            line_ref = f" (Line {s.line})" if s.line else ""
            lines.append(
                f"- [{s.kind or 'smell'}] **{s.title}**{line_ref} — `{s.severity.upper()}`"
            )
    elif smells:
        lines.append(
            f"*Code Smells: {len(smells)} (omitted to fit token budget)*"
        )

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

# Map file extension → Markdown fenced-code language identifier
_EXT_LANG: dict[str, str] = {
    ".py":   "python",
    ".ts":   "typescript",
    ".tsx":  "tsx",
    ".js":   "javascript",
    ".jsx":  "jsx",
    ".mjs":  "javascript",
    ".go":   "go",
    ".rs":   "rust",
    ".java": "java",
    ".kt":   "kotlin",
    ".rb":   "ruby",
    ".php":  "php",
    ".cs":   "csharp",
    ".cpp":  "cpp",
    ".c":    "c",
    ".sh":   "bash",
    ".md":   "markdown",
    ".json": "json",
    ".yaml": "yaml",
    ".yml":  "yaml",
    ".toml": "toml",
    ".html": "html",
    ".css":  "css",
    ".sql":  "sql",
}


def _lang_from_file(file: str) -> str:
    """Return a Markdown code-fence language tag for *file*'s extension."""
    if not file:
        return ""
    ext = os.path.splitext(file)[1].lower()
    return _EXT_LANG.get(ext, "")


def _sev_order(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
        severity.lower(), 0
    )


def _trim_snippet(snippet: str, max_lines: int) -> str:
    """Return *snippet* capped to *max_lines*, with a truncation note if cut."""
    all_lines = snippet.splitlines()
    if len(all_lines) <= max_lines:
        return snippet
    kept = all_lines[:max_lines]
    kept.append(f"... ({len(all_lines) - max_lines} lines omitted)")
    return "\n".join(kept)


def _estimate_tokens(text: str) -> int:
    """Heuristic token count: 4 characters ≈ 1 token."""
    return max(1, len(text) // _CHARS_PER_TOKEN)


def _build_metadata(
    result: AnalysisResult,
    correlation_report: CorrelationReport,
) -> dict[str, Any]:
    repo = result.repository
    return {
        "repo_name":      repo.name or "unknown",
        "branch":         repo.branch or "unknown",
        "commit_hash":    repo.commit_hash or "unknown",
        "languages":      repo.language,
        "frameworks":     repo.frameworks,
        "analysis_date":  datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_clusters": correlation_report.total_clusters,
        "total_hotspots": sum(
            1 for c in correlation_report.clusters if c.is_hotspot
        ),
    }


def _empty_prompt(result: AnalysisResult) -> str:
    repo_name = result.repository.name or "Unknown Repository"
    return (
        f"# AUDIT CONTEXT: {repo_name}\n\n"
        "## EXECUTIVE RISK SUMMARY\n\n"
        "No hotspot clusters were detected. "
        "The repository appears low-risk based on current findings.\n"
    )
