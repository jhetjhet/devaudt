from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import logging

import networkx as nx

logger = logging.getLogger(__name__)

from .base import BaseAnalyzer
from .models import (
    AnalysisResult, ArchitectureInfo, DependenciesInfo, EvidenceEntry,
    ImportEdge, MetricsInfo, RelationshipsInfo, RepositoryInfo, SecurityInfo,
    UnusedDependency,
)
from .repository import RepositoryScanner
from .scoring import batch_unused_confidence


def analyze_local(repo_path: str) -> AnalysisResult:
    """
    Run the full deterministic analysis on a locally checked-out repository.
    This is the primary API entry point.
    """
    logger.info("Scanning repository: %s", repo_path)
    scanner = RepositoryScanner(repo_path)
    all_files = scanner.get_files()
    logger.debug("Found %d source file(s)", len(all_files))

    langs = scanner.detect_languages(all_files)
    logger.info("Detected language(s): %s", langs)

    analyzers: list[BaseAnalyzer] = []

    if "python" in langs:
        from .python.analyzer import PythonAnalyzer
        analyzers.append(PythonAnalyzer(repo_path))

    if "typescript" in langs or "javascript" in langs:
        from .typescript.analyzer import TypeScriptAnalyzer
        analyzers.append(TypeScriptAnalyzer(repo_path))

    logger.info(
        "Dispatching %d analyzer(s): %s",
        len(analyzers),
        [type(a).__name__ for a in analyzers],
    )

    partial_results: list[tuple[BaseAnalyzer, AnalysisResult]] = []
    for analyzer in analyzers:
        logger.info("Running %s…", type(analyzer).__name__)
        result = analyzer.analyze()
        partial_results.append((analyzer, result))
        logger.info("%s complete", type(analyzer).__name__)

    logger.info("Merging results from %d analyzer(s)…", len(partial_results))
    return _merge(scanner, all_files, langs, partial_results)


def analyze_url(repo_url: str) -> AnalysisResult:
    """
    Clone *repo_url* into a temporary sandbox and run analyze_local().
    The temporary directory is deleted automatically after analysis.
    """
    logger.info("Cloning %s (depth=50)…", repo_url)
    with tempfile.TemporaryDirectory() as tmp_dir:
        subprocess.run(
            ["git", "clone", "--depth", "50", repo_url, tmp_dir],
            check=True,
        )
        logger.info("Clone complete")
        return analyze_local(tmp_dir)


# ---------------------------------------------------------------------------
# Internal merge
# ---------------------------------------------------------------------------

def _merge(
    scanner: RepositoryScanner,
    all_files: list[str],
    langs: list[str],
    partial_results: list[tuple[BaseAnalyzer, AnalysisResult]],
) -> AnalysisResult:
    logger.debug("_merge: %d partial result(s)", len(partial_results))

    # ---- repository ---------------------------------------------------
    frameworks = scanner.detect_frameworks(all_files)
    repository = RepositoryInfo(
        name=scanner.root.name,
        language=sorted(langs),
        frameworks=sorted(frameworks),
        commit_hash=scanner.get_commit_hash(),
        branch=scanner.get_branch(),
        file_count=len(all_files),
    )

    # ---- merge per-analyzer data -------------------------------------
    all_findings = []
    all_smells = []
    all_sec_findings = []
    all_evidence: dict[str, EvidenceEntry] = {}
    all_import_edges: list[tuple[str, str]] = []

    total_funcs = 0
    total_func_lines = 0.0
    high_complexity = 0
    todo_count = 0
    outdated_packages = []
    # Collect raw declared-but-not-imported names; confidence scored below
    raw_unused_names: list[str] = []
    # Collect the actual used modules reported by each analyzer
    all_used_modules: set[str] = set()
    all_circular: list[list[str]] = []

    for analyzer, result in partial_results:
        all_findings.extend(result.findings)
        all_smells.extend(result.code_smells)
        all_sec_findings.extend(result.security.findings)
        all_evidence.update(analyzer._evidence_index)
        all_import_edges.extend(analyzer._import_edges)
        # circular deps collected by each analyzer (Python: list[list[str]])
        all_circular.extend(getattr(analyzer, "_circular_deps", []))

        total_funcs += result.metrics.total_functions
        total_func_lines += (
            result.metrics.avg_function_length * result.metrics.total_functions
        )
        high_complexity += result.metrics.high_complexity_functions
        todo_count += result.metrics.todo_count
        outdated_packages.extend(result.dependencies.outdated_packages)

        # Collect raw unused names from each analyzer
        for ud in result.dependencies.unused_dependencies:
            # Analyzers may emit UnusedDependency or plain str depending on
            # whether they have already been scored
            if isinstance(ud, UnusedDependency):
                raw_unused_names.append(ud.name)
            else:
                raw_unused_names.append(str(ud))

        # Collect used module names from import edges (source side)
        for src, _ in analyzer._import_edges:
            all_used_modules.add(src)

    logger.debug(
        "Collected: %d finding(s), %d smell(s), %d security finding(s), %d import edge(s)",
        len(all_findings), len(all_smells), len(all_sec_findings), len(all_import_edges),
    )
    avg_func_len = round(total_func_lines / total_funcs, 1) if total_funcs else 0.0

    # ---- security -----------------------------------------------------
    sec_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sf in all_sec_findings:
        if sf.severity in sec_counts:
            sec_counts[sf.severity] += 1
    security = SecurityInfo(
        critical_count=sec_counts["critical"],
        high_count=sec_counts["high"],
        medium_count=sec_counts["medium"],
        low_count=sec_counts["low"],
        findings=sorted(all_sec_findings, key=lambda s: (s.file, s.line, s.type)),
    )
    logger.info(
        "Security totals: critical=%d high=%d medium=%d low=%d",
        sec_counts["critical"], sec_counts["high"],
        sec_counts["medium"], sec_counts["low"],
    )

    # ---- architecture -------------------------------------------------
    pattern = scanner.detect_architecture_pattern(all_files)
    services = scanner.detect_services(all_files)

    architecture = ArchitectureInfo(
        detected_pattern=pattern,
        services=services,
    )
    logger.info("Architecture: pattern=%s, services=%s", pattern, services)

    # ---- relationships graph -----------------------------------------
    logger.info("Building relationship graph…")
    relationships = _build_relationships(all_import_edges, all_files, all_circular)

    # ---- metrics ------------------------------------------------------
    metrics = MetricsInfo(
        total_functions=total_funcs,
        avg_function_length=avg_func_len,
        high_complexity_functions=high_complexity,
        todo_count=todo_count,
    )

    # ---- dependencies -------------------------------------------------
    # Dedup outdated by package name (first wins)
    seen_pkg: set[str] = set()
    deduped_outdated = []
    for pkg in outdated_packages:
        if pkg.name not in seen_pkg:
            seen_pkg.add(pkg.name)
            deduped_outdated.append(pkg)

    # Score unused dependencies with repo-context confidence
    scored_unused_dicts = batch_unused_confidence(
        unused_names=list(set(raw_unused_names)),
        used_modules=all_used_modules,
        repo_path=scanner.root,
    )
    scored_unused = [
        UnusedDependency(
            name=d["name"],
            confidence=d["confidence"],
            reasons=d["reasons"],
        )
        for d in scored_unused_dicts
    ]

    dependencies = DependenciesInfo(
        outdated_packages=sorted(deduped_outdated, key=lambda p: p.name),
        unused_dependencies=sorted(scored_unused, key=lambda u: u.name),
    )
    logger.debug(
        "Dependencies: %d outdated, %d unused",
        len(deduped_outdated), len(scored_unused),
    )

    # ---- deduplicate findings & smells by stable ID ------------------
    def _dedup(items):
        seen: set[str] = set()
        out = []
        for item in sorted(items, key=lambda x: (x.file, x.line, x.type)):
            if item.id not in seen:
                seen.add(item.id)
                out.append(item)
        return out

    deduped_findings = _dedup(all_findings)
    deduped_smells = _dedup(all_smells)
    logger.info(
        "Analysis complete: %d finding(s), %d code smell(s), %d security finding(s)",
        len(deduped_findings), len(deduped_smells), len(security.findings),
    )
    return AnalysisResult(
        repository=repository,
        architecture=architecture,
        metrics=metrics,
        dependencies=dependencies,
        findings=deduped_findings,
        security=security,
        code_smells=deduped_smells,
        change_set=scanner.get_change_set(),
        relationships=relationships,
        evidence_index=dict(sorted(all_evidence.items())),
    )


# ---------------------------------------------------------------------------
# Relationship / graph construction
# ---------------------------------------------------------------------------

def _build_relationships(
    raw_edges: list[tuple[str, str]],
    all_files: list[str],
    all_circular: list[list[str]],
) -> RelationshipsInfo:
    """
    Build a deterministic RelationshipsInfo from raw import edges.
    """
    logger.debug(
        "_build_relationships: %d raw edge(s), %d total file(s)",
        len(raw_edges), len(all_files),
    )
    # Deduplicate edges while preserving order (first occurrence wins)
    seen_edge: set[tuple[str, str]] = set()
    unique_edges: list[ImportEdge] = []
    for src, tgt in sorted(raw_edges):
        if (src, tgt) not in seen_edge:
            seen_edge.add((src, tgt))
            unique_edges.append(ImportEdge(source=src, target=tgt))

    # Nodes: every file that participates in at least one edge
    nodes: set[str] = set()
    for e in unique_edges:
        nodes.add(e.source)
        nodes.add(e.target)

    # Coupling score via networkx density
    g = nx.DiGraph()
    g.add_nodes_from(all_files)
    g.add_edges_from((e.source, e.target) for e in unique_edges)
    coupling = round(nx.density(g), 4) if len(all_files) >= 2 else 0.0

    # Deduplicate cycles
    seen_cycles: set[frozenset] = set()
    unique_cycles: list[list[str]] = []
    for cycle in all_circular:
        key = frozenset(cycle)
        if key not in seen_cycles:
            seen_cycles.add(key)
            unique_cycles.append(sorted(cycle))

    logger.info(
        "Relationship graph: %d node(s), %d edge(s), %d cycle(s), coupling=%.4f",
        len(nodes), len(unique_edges), len(unique_cycles), coupling,
    )
    return RelationshipsInfo(
        nodes=sorted(nodes),
        edges=unique_edges,
        cycles=sorted(unique_cycles),
        coupling_score=coupling,
    )
