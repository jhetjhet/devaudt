from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

from ..base import BaseAnalyzer
from ..models import (
    AnalysisResult, ArchitectureInfo, CodeSmell, DependenciesInfo, Evidence,
    Finding, MetricsInfo, OutdatedPackage, SecurityFinding, SecurityInfo,
)
from ..repository import IGNORE_DIRS

# ---------------------------------------------------------------------------
# Thresholds (mirrors the Python analyzer)
# ---------------------------------------------------------------------------
_FUNC_LINES_MEDIUM = 50
_FUNC_LINES_HIGH = 150
_CLASS_LINES_MEDIUM = 200
_CLASS_LINES_HIGH = 500
_COMPLEXITY_MEDIUM = 10
_COMPLEXITY_HIGH = 15
_GOD_METHODS_MEDIUM = 15
_GOD_METHODS_HIGH = 20
_NESTING_MEDIUM = 4
_PARAM_LOW = 5
_PARAM_MEDIUM = 8

# ---------------------------------------------------------------------------
# Security regex (applied to raw source lines)
# ---------------------------------------------------------------------------
_SECRET_RE: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(
            r'(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token'
            r'|client[_-]?secret)\s*[:=]\s*["\'][A-Za-z0-9_\-\.\/+]{8,}["\']'
        ),
        "hardcoded_secret", "medium",
    ),
    (
        re.compile(r'(?i)password\s*[:=]\s*["\'][^"\']{4,}["\']'),
        "hardcoded_password", "high",
    ),
    (
        re.compile(r'(?i)private[_-]?key\s*[:=]\s*["\'][^"\']+["\']'),
        "hardcoded_private_key", "critical",
    ),
]

_TODO_RE = re.compile(r"//\s*(?:TODO|FIXME|HACK|XXX)\b", re.IGNORECASE)

# Node script path (sibling directory)
_NODE_SCRIPT = Path(__file__).parent / "node" / "analyze.mjs"


class TypeScriptAnalyzer(BaseAnalyzer):
    """
    Deterministic analyzer for TypeScript and JavaScript repositories.

    Uses a bundled Node.js helper (analyze.mjs) that invokes ts-morph for
    AST analysis and madge for dependency/cycle detection.  Falls back
    gracefully when Node.js or npm packages are unavailable.
    """

    supported_extensions = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]

    def analyze(self) -> AnalysisResult:
        logger.info("TypeScriptAnalyzer: attempting Node.js analysis…")
        node_data = self._run_node_analysis()

        if node_data is None:
            logger.info("Node.js tooling unavailable — falling back to regex-only analysis")
            return self._fallback_analysis()

        functions   = node_data.get("functions", [])
        classes     = node_data.get("classes", [])
        imports     = node_data.get("imports", [])
        todos       = node_data.get("todos", [])
        dep_graph   = node_data.get("dep_graph", {})
        circular    = node_data.get("circular_dependencies", [])
        node_sec    = node_data.get("security", [])
        logger.info(
            "Node.js data: %d function(s), %d class(es), %d import(s), "
            "%d todo(s), %d security finding(s)",
            len(functions), len(classes), len(imports), len(todos), len(node_sec),
        )

        findings:      list[Finding] = []
        smells:        list[CodeSmell] = []
        sec_findings:  list[SecurityFinding] = []

        # --- convert Node security findings -------------------------------
        for ns in node_sec:
            sec_findings.append(SecurityFinding(
                type=ns.get("type", "unknown"),
                file=ns.get("file", ""),
                line=ns.get("line", 0),
                severity=ns.get("severity", "medium"),
                description=ns.get("description", ""),
            ))

        # --- per-function analysis ----------------------------------------
        for fn in functions:
            rel      = fn.get("file", "")
            name     = fn.get("name", "<anonymous>")
            lineno   = fn.get("start_line", 0)
            line_count = fn.get("line_count", 0)
            complexity = fn.get("complexity", 1)
            param_count = fn.get("param_count", 0)

            # Large function
            if line_count >= _FUNC_LINES_HIGH:
                sev = "high"
            elif line_count >= _FUNC_LINES_MEDIUM:
                sev = "medium"
            else:
                sev = None

            if sev:
                fid = self.make_finding_id(rel, name, "large_function")
                findings.append(Finding(
                    id=fid, type="large_function", severity=sev,
                    title="Large Function Detected",
                    file=rel, symbol=name, line=lineno,
                    evidence=[
                        Evidence(type="line_count", value=line_count,
                                 threshold=_FUNC_LINES_MEDIUM),
                        Evidence(type="complexity", value=complexity,
                                 threshold=_COMPLEXITY_MEDIUM),
                    ],
                ))

            # High complexity
            if complexity >= _COMPLEXITY_HIGH:
                csev = "high"
            elif complexity >= _COMPLEXITY_MEDIUM:
                csev = "medium"
            else:
                csev = None

            if csev:
                fid = self.make_finding_id(rel, name, "high_complexity")
                findings.append(Finding(
                    id=fid, type="high_complexity", severity=csev,
                    title="High Cyclomatic Complexity",
                    file=rel, symbol=name, line=lineno,
                    evidence=[Evidence(type="complexity", value=complexity,
                                       threshold=_COMPLEXITY_MEDIUM)],
                ))

            # Long parameter list
            if param_count >= _PARAM_MEDIUM:
                psev = "medium"
            elif param_count >= _PARAM_LOW:
                psev = "low"
            else:
                psev = None
            if psev:
                sid = self.make_finding_id(rel, name, "long_parameter_list")
                smells.append(CodeSmell(
                    id=sid, type="long_parameter_list", severity=psev,
                    title="Long Parameter List",
                    file=rel, symbol=name, line=lineno,
                    evidence=[Evidence(type="param_count", value=param_count,
                                       threshold=_PARAM_LOW)],
                ))

        # --- per-class analysis -------------------------------------------
        for cls in classes:
            rel       = cls.get("file", "")
            name      = cls.get("name", "<anonymous>")
            lineno    = cls.get("start_line", 0)
            line_count = cls.get("line_count", 0)
            mc        = cls.get("method_count", 0)

            if line_count >= _CLASS_LINES_HIGH:
                csev = "high"
            elif line_count >= _CLASS_LINES_MEDIUM:
                csev = "medium"
            else:
                csev = None
            if csev:
                sid = self.make_finding_id(rel, name, "large_class")
                smells.append(CodeSmell(
                    id=sid, type="large_class", severity=csev,
                    title="Large Class Detected",
                    file=rel, symbol=name, line=lineno,
                    evidence=[Evidence(type="line_count", value=line_count,
                                       threshold=_CLASS_LINES_MEDIUM)],
                ))

            if mc >= _GOD_METHODS_HIGH:
                gsev = "high"
            elif mc >= _GOD_METHODS_MEDIUM:
                gsev = "medium"
            else:
                gsev = None
            if gsev:
                sid = self.make_finding_id(rel, name, "god_object")
                smells.append(CodeSmell(
                    id=sid, type="god_object", severity=gsev,
                    title="God Object / Class Too Large",
                    file=rel, symbol=name, line=lineno,
                    evidence=[Evidence(type="method_count", value=mc,
                                       threshold=_GOD_METHODS_MEDIUM)],
                ))

        # --- import graph & edges ----------------------------------------
        internal_files = {fn.get("file") for fn in functions} | \
                         {cls.get("file") for cls in classes}
        for src_file, deps in dep_graph.items():
            for dep in deps:
                if dep in internal_files:
                    self._import_edges.append((src_file, dep))

        # --- source-level security scan (regex fallback) -----------------
        for rel in self._collect_files():
            abs_path = self.repo_path / rel
            try:
                src = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for pat, ftype, sev in _SECRET_RE:
                for m in pat.finditer(src):
                    lineno = src[: m.start()].count("\n") + 1
                    sec_findings.append(SecurityFinding(
                        type=ftype, file=rel, line=lineno, severity=sev,
                        description=ftype,
                    ))

        # --- dependency intelligence -------------------------------------
        logger.info("Analyzing TypeScript/JavaScript dependencies…")
        outdated, unused = self._analyze_package_json(imports)

        # --- metrics -------------------------------------------------------
        func_lengths = [f.get("line_count", 0) for f in functions]
        avg_len = round(sum(func_lengths) / len(func_lengths), 1) if func_lengths else 0.0
        high_cx = sum(1 for f in functions if f.get("complexity", 0) >= _COMPLEXITY_MEDIUM)
        todo_count = len(todos)

        sec_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sf in sec_findings:
            if sf.severity in sec_counts:
                sec_counts[sf.severity] += 1

        self._circular_deps = [sorted(c) for c in circular]

        return AnalysisResult(
            metrics=MetricsInfo(
                total_functions=len(functions),
                avg_function_length=avg_len,
                high_complexity_functions=high_cx,
                todo_count=todo_count,
            ),
            findings=findings,
            security=SecurityInfo(
                critical_count=sec_counts["critical"],
                high_count=sec_counts["high"],
                medium_count=sec_counts["medium"],
                low_count=sec_counts["low"],
                findings=sec_findings,
            ),
            code_smells=smells,
            architecture=ArchitectureInfo(),
            dependencies=DependenciesInfo(
                outdated_packages=outdated,
                unused_dependencies=unused,
            ),
        )

    # ------------------------------------------------------------------
    # Node.js bridge
    # ------------------------------------------------------------------

    def _run_node_analysis(self) -> dict | None:
        """
        Run the bundled Node.js analysis script.
        Returns parsed JSON dict or None if Node.js / npm is unavailable.
        """
        node_dir = _NODE_SCRIPT.parent

        # Auto-install npm dependencies on first run
        nm = node_dir / "node_modules"
        if not nm.exists():
            logger.info("Installing Node.js dependencies in %s…", node_dir)
            ok = self._npm_install(node_dir)
            if not ok:
                logger.warning("npm install failed — Node.js analysis disabled")
                return None

        logger.debug("Running Node.js analysis script: %s", _NODE_SCRIPT)
        try:
            proc = subprocess.run(
                ["node", str(_NODE_SCRIPT), str(self.repo_path)],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                logger.warning("Node.js script exited with code %d", proc.returncode)
                return None
            logger.debug("Node.js script returned %d byte(s)", len(proc.stdout))
            return json.loads(proc.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            logger.warning("Node.js analysis error: %s", exc)
            return None

    @staticmethod
    def _npm_install(node_dir: Path) -> bool:
        try:
            subprocess.run(
                ["npm", "install", "--prefer-offline", "--no-audit"],
                cwd=node_dir, capture_output=True, check=True, timeout=120,
            )
            return True
        except (FileNotFoundError, subprocess.CalledProcessError,
                subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------
    # Fallback (no Node.js)
    # ------------------------------------------------------------------

    def _fallback_analysis(self) -> AnalysisResult:
        """Regex-only analysis when Node.js tooling is unavailable."""
        files = self._collect_files()
        logger.info("TypeScriptAnalyzer fallback: %d file(s) to scan", len(files))
        sec_findings: list[SecurityFinding] = []
        todo_count = 0

        for rel in files:
            abs_path = self.repo_path / rel
            try:
                src = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = src.splitlines()
            todo_count += sum(1 for ln in lines if _TODO_RE.search(ln))
            for pat, ftype, sev in _SECRET_RE:
                for m in pat.finditer(src):
                    lineno = src[: m.start()].count("\n") + 1
                    sec_findings.append(SecurityFinding(
                        type=ftype, file=rel, line=lineno, severity=sev,
                        description=ftype,
                    ))

        sec_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sf in sec_findings:
            if sf.severity in sec_counts:
                sec_counts[sf.severity] += 1

        outdated, unused = self._analyze_package_json([])
        return AnalysisResult(
            metrics=MetricsInfo(todo_count=todo_count),
            security=SecurityInfo(
                critical_count=sec_counts["critical"],
                high_count=sec_counts["high"],
                medium_count=sec_counts["medium"],
                low_count=sec_counts["low"],
                findings=sec_findings,
            ),
            dependencies=DependenciesInfo(
                outdated_packages=outdated,
                unused_dependencies=unused,
            ),
        )

    # ------------------------------------------------------------------
    # Dependency analysis
    # ------------------------------------------------------------------

    def _analyze_package_json(
        self, imports: list[dict]
    ) -> tuple[list[OutdatedPackage], list[str]]:
        pkg_json = self.repo_path / "package.json"
        if not pkg_json.exists():
            return [], []

        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return [], []

        declared: dict[str, str] = {}
        declared.update(data.get("dependencies", {}))
        declared.update(data.get("devDependencies", {}))
        logger.debug("package.json: %d declared package(s)", len(declared))

        # Modules actually imported in source
        used_modules: set[str] = {
            imp.get("module", "").split("/")[0].lstrip("@").split("/")[0]
            for imp in imports
            if not imp.get("module", "").startswith(".")
        }
        # Also include @scope/pkg
        used_scoped: set[str] = set()
        for imp in imports:
            mod = imp.get("module", "")
            if mod.startswith("@"):
                parts = mod.split("/")
                if len(parts) >= 2:
                    used_scoped.add(f"{parts[0]}/{parts[1]}")
        used_modules |= used_scoped

        unused = sorted(
            name for name in declared
            if name.split("/")[-1] not in used_modules
            and name not in used_modules
        )

        # Version intelligence via npm registry
        if declared:
            logger.info("Checking npm registry for outdated packages (%d)…", len(declared))
        outdated: list[OutdatedPackage] = []
        for name, ver_spec in declared.items():
            current = _clean_semver(ver_spec)
            if not current:
                continue
            latest = _fetch_npm_latest(name)
            if latest and _semver_lt(current, latest):
                outdated.append(OutdatedPackage(
                    name=name, current=current, recommended=latest
                ))

        logger.debug(
            "npm deps result: %d unused, %d outdated",
            len(unused), len(outdated),
        )
        return sorted(outdated, key=lambda p: p.name), unused

    # ------------------------------------------------------------------
    # File collection
    # ------------------------------------------------------------------

    def _collect_files(self) -> list[str]:
        exts = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
        result: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self.repo_path):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in IGNORE_DIRS and not d.startswith(".")
            )
            for name in sorted(filenames):
                if Path(name).suffix in exts:
                    rel = Path(dirpath, name).relative_to(self.repo_path).as_posix()
                    result.append(rel)
        return result


# ---------------------------------------------------------------------------
# Npm helpers
# ---------------------------------------------------------------------------

def _clean_semver(spec: str) -> str | None:
    """Strip semver range prefixes like ^, ~, >=."""
    m = re.search(r"(\d+\.\d+[\.\d]*)", spec)
    return m.group(1) if m else None


def _fetch_npm_latest(name: str) -> str | None:
    try:
        import requests
        r = requests.get(
            f"https://registry.npmjs.org/{name}/latest",
            timeout=5,
        )
        if r.status_code == 200:
            return r.json().get("version")
    except Exception:
        pass
    return None


def _semver_lt(current: str, latest: str) -> bool:
    try:
        from packaging.version import Version
        return Version(current) < Version(latest)
    except Exception:
        return False
