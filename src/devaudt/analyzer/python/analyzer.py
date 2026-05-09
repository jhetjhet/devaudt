from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import logging

import networkx as nx

logger = logging.getLogger(__name__)

from ..base import BaseAnalyzer, extract_snippet
from ..models import (
    AnalysisResult, ArchitectureInfo, AuditContext, AuditObject, CodeSmell,
    DependenciesInfo, Evidence, Finding, MetricsInfo, OutdatedPackage,
)
from ..repository import IGNORE_DIRS

# ---------------------------------------------------------------------------
# Thresholds
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
# Radon availability
# ---------------------------------------------------------------------------
try:
    from radon.complexity import cc_visit as _radon_cc_visit
    _RADON_OK = True
except ImportError:
    _RADON_OK = False

# ---------------------------------------------------------------------------
# Security regex patterns  (pattern, finding_type, severity)
# ---------------------------------------------------------------------------
_SECRET_RE: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(
            r'(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token'
            r'|client[_-]?secret)\s*=\s*["\'][A-Za-z0-9_\-\.\/+]{8,}["\']'
        ),
        "hardcoded_secret", "medium",
    ),
    (
        re.compile(r'(?i)password\s*=\s*["\'][^"\']{4,}["\']'),
        "hardcoded_password", "high",
    ),
    (
        re.compile(r'(?i)private[_-]?key\s*=\s*["\'][^"\']+["\']'),
        "hardcoded_private_key", "critical",
    ),
    (
        re.compile(
            r'(?i)(?:db_|database_)?(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']'
        ),
        "hardcoded_db_password", "high",
    ),
]

_TODO_RE = re.compile(r"#\s*(?:TODO|FIXME|HACK|XXX)\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _max_nesting_depth(root: ast.AST) -> int:
    """Maximum control-flow nesting depth inside *root*."""
    _CONTROL = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.ExceptHandler)

    def _walk(node: ast.AST, depth: int) -> int:
        best = depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _CONTROL):
                best = max(best, _walk(child, depth + 1))
            else:
                best = max(best, _walk(child, depth))
        return best

    return _walk(root, 0)


def _ast_complexity(func_node: ast.AST) -> int:
    """Fallback cyclomatic complexity: 1 + count of branch nodes."""
    _BRANCHES = (
        ast.If, ast.For, ast.While, ast.ExceptHandler,
        ast.Assert, ast.comprehension,
    )
    count = 1
    for node in ast.walk(func_node):
        if isinstance(node, _BRANCHES):
            count += 1
        elif isinstance(node, ast.BoolOp):
            count += len(node.values) - 1
    return count


def _func_complexity(source: str, func_name: str, func_node: ast.AST) -> int:
    if _RADON_OK:
        try:
            for block in _radon_cc_visit(source):
                if block.name == func_name:
                    return block.complexity
        except Exception:
            pass
    return _ast_complexity(func_node)


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------

def _parse_requirements_txt(path: Path) -> dict[str, str]:
    """Return {name: version_spec} from a requirements.txt file."""
    packages: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "http")):
                continue
            # Strip extras: package[extra]>=1.0 → package, >=1.0
            m = re.match(r"^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?\s*([><=!~^].*?)?$", line)
            if m:
                name = m.group(1).lower()
                spec = (m.group(2) or "").strip()
                packages[name] = spec
    except Exception:
        pass
    return packages


def _parse_pyproject_toml(path: Path) -> dict[str, str]:
    packages: dict[str, str] = {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
        # PEP 621 / Flit
        for dep in data.get("project", {}).get("dependencies", []):
            m = re.match(r"^([A-Za-z0-9_\-\.]+)", dep)
            if m:
                packages[m.group(1).lower()] = dep
        # Poetry
        for name, ver in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
            if name.lower() != "python":
                packages[name.lower()] = str(ver)
    except Exception:
        pass
    return packages


def _fetch_pypi_latest(name: str) -> str | None:
    try:
        import requests
        r = requests.get(
            f"https://pypi.org/pypi/{name}/json", timeout=5
        )
        if r.status_code == 200:
            return r.json()["info"]["version"]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Pylint integration
# ---------------------------------------------------------------------------

_PYLINT_SYMBOL_MAP: dict[str, tuple[str, str]] = {
    # symbol → (finding_type, severity)
    "too-many-statements":     ("large_function",      "medium"),
    "too-many-branches":       ("high_complexity",     "medium"),
    "too-many-arguments":      ("long_parameter_list", "low"),
    "too-many-instance-attributes": ("god_object",     "medium"),
    "too-many-public-methods": ("god_object",          "medium"),
    "eval-used":               ("eval_usage",          "high"),
    "exec-used":               ("eval_usage",          "high"),
    "broad-exception-caught":  ("broad_exception",     "low"),
    "dangerous-default-value": ("dangerous_default",   "medium"),
    "subprocess-run-check":    ("unchecked_subprocess","low"),
    "bare-except":             ("bare_except",         "low"),
}

# kind for each pylint-derived finding type (used in to_dict / hotspot map)
_PYLINT_TYPE_KIND: dict[str, str] = {
    "large_function":       "performance",
    "high_complexity":      "performance",
    "long_parameter_list":  "maintainability",
    "god_object":           "maintainability",
    "eval_usage":           "security",
    "broad_exception":      "reliability",
    "dangerous_default":    "reliability",
    "unchecked_subprocess": "reliability",
    "bare_except":          "reliability",
}


def _run_pylint(repo_path: Path, py_files: list[str]) -> list[dict]:
    if not py_files:
        return []
    # Cap at 50 files to keep runtime manageable
    sample = py_files[:50]
    abs_files = [str(repo_path / f) for f in sample]
    try:
        proc = subprocess.run(
            [
                sys.executable, "-m", "pylint",
                "--output-format", "json",
                "--score", "n",
                "--disable", "all",
                "--enable", ",".join(_PYLINT_SYMBOL_MAP.keys()),
                *abs_files,
            ],
            capture_output=True, text=True,
            cwd=repo_path,
        )
        if proc.stdout.strip():
            return json.loads(proc.stdout)
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class PythonAnalyzer(BaseAnalyzer):
    """Deterministic analyzer for Python repositories."""

    supported_extensions = [".py"]

    def analyze(self) -> AnalysisResult:
        scanner_files = self._collect_files()
        if not scanner_files:
            logger.info("PythonAnalyzer: no Python files found, skipping")
            return AnalysisResult()

        source_files = [f for f in scanner_files if not _is_test_file(f)]
        test_files   = [f for f in scanner_files if _is_test_file(f)]
        logger.info(
            "PythonAnalyzer: %d source file(s), %d test file(s)",
            len(source_files), len(test_files),
        )

        # Per-file analysis via AST
        all_funcs:    list[dict] = []
        all_classes:  list[dict] = []
        all_imports:  list[dict] = []
        todo_count = 0
        sec_findings: list[Finding] = []
        smells:       list[CodeSmell] = []
        findings:     list[Finding] = []

        for rel in source_files:
            logger.debug("Analyzing %s", rel)
            abs_path = self.repo_path / rel
            try:
                src = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            try:
                tree = ast.parse(src, filename=rel)
            except SyntaxError:
                continue

            lines = src.splitlines()
            todo_count += sum(1 for ln in lines if _TODO_RE.search(ln))

            # --- security (regex on source) ---------------------------------
            for pat, ftype, sev in _SECRET_RE:
                for m in pat.finditer(src):
                    lineno = src[: m.start()].count("\n") + 1
                    _key = f"{rel}\x00{lineno}\x00{ftype}"
                    fid = "FIND-" + hashlib.sha256(_key.encode()).hexdigest()[:8].upper()
                    eid = self.make_entity_id(rel, "file", rel)
                    sec_findings.append(Finding(
                        id=fid, type=ftype, file=rel, line=lineno, severity=sev,
                        title=pat.pattern[:60], kind="security",
                        entity_id=eid,
                        snippet=extract_snippet(src, lineno),
                    ))

            # --- collect AST nodes ----------------------------------------
            file_funcs, file_classes, file_imports = _collect_ast(src, tree, rel)
            all_funcs.extend(file_funcs)
            all_classes.extend(file_classes)
            all_imports.extend(file_imports)

            # --- per-function analysis ------------------------------------
            for fn in file_funcs:
                node = fn["_node"]
                complexity = _func_complexity(src, fn["name"], node)
                fn["complexity"] = complexity

                # Code smells -----------------------------------------------
                if fn["line_count"] >= _FUNC_LINES_HIGH:
                    sev = "high"
                elif fn["line_count"] >= _FUNC_LINES_MEDIUM:
                    sev = "medium"
                else:
                    sev = None

                if sev:
                    fid = self.make_finding_id(rel, fn["name"], "large_function")
                    evid = self.make_evidence_id(rel, fn["lineno"], "line_count")
                    eid = self.make_entity_id(rel, "function", fn["name"])
                    _end = fn["lineno"] + fn["line_count"] - 1
                    findings.append(Finding(
                        id=fid, type="large_function", severity=sev,
                        title="Large Function Detected",
                        file=rel, symbol=fn["name"], line=fn["lineno"],
                        end_line=_end,
                        snippet=extract_snippet(src, fn["lineno"], _end),
                        entity_id=eid,
                        kind="performance",
                        evidence=[
                            Evidence(type="line_count", value=fn["line_count"],
                                     threshold=_FUNC_LINES_MEDIUM),
                            Evidence(type="complexity", value=complexity,
                                     threshold=_COMPLEXITY_MEDIUM),
                        ],
                    ))

                if complexity >= _COMPLEXITY_HIGH:
                    csev = "high"
                elif complexity >= _COMPLEXITY_MEDIUM:
                    csev = "medium"
                else:
                    csev = None

                if csev:
                    fid = self.make_finding_id(rel, fn["name"], "high_complexity")
                    eid = self.make_entity_id(rel, "function", fn["name"])
                    _end = fn["lineno"] + fn["line_count"] - 1
                    findings.append(Finding(
                        id=fid, type="high_complexity", severity=csev,
                        title="High Cyclomatic Complexity",
                        file=rel, symbol=fn["name"], line=fn["lineno"],
                        end_line=_end,
                        snippet=extract_snippet(src, fn["lineno"], _end),
                        entity_id=eid,
                        kind="performance",
                        evidence=[
                            Evidence(type="complexity", value=complexity,
                                     threshold=_COMPLEXITY_MEDIUM),
                        ],
                    ))

                # Nesting
                nesting = _max_nesting_depth(node)
                if nesting >= _NESTING_MEDIUM:
                    sid = self.make_finding_id(rel, fn["name"], "deep_nesting")
                    eid = self.make_entity_id(rel, "function", fn["name"])
                    _end = fn["lineno"] + fn["line_count"] - 1
                    smells.append(CodeSmell(
                        id=sid, type="deep_nesting", severity="medium",
                        title="Deep Nesting Detected",
                        file=rel, symbol=fn["name"], line=fn["lineno"],
                        end_line=_end,
                        snippet=extract_snippet(src, fn["lineno"], _end),
                        entity_id=eid,
                        kind="maintainability",
                        evidence=[Evidence(type="nesting_depth", value=nesting,
                                           threshold=_NESTING_MEDIUM)],
                    ))

                # Long parameter list
                param_count = fn["param_count"]
                if param_count >= _PARAM_MEDIUM:
                    psev = "medium"
                elif param_count >= _PARAM_LOW:
                    psev = "low"
                else:
                    psev = None
                if psev:
                    sid = self.make_finding_id(rel, fn["name"], "long_parameter_list")
                    eid = self.make_entity_id(rel, "function", fn["name"])
                    smells.append(CodeSmell(
                        id=sid, type="long_parameter_list", severity=psev,
                        title="Long Parameter List",
                        file=rel, symbol=fn["name"], line=fn["lineno"],
                        snippet=extract_snippet(src, fn["lineno"]),
                        entity_id=eid,
                        kind="maintainability",
                        evidence=[Evidence(type="param_count", value=param_count,
                                           threshold=_PARAM_LOW)],
                    ))

            # --- per-class analysis ----------------------------------------
            for cls in file_classes:
                # Large class
                if cls["line_count"] >= _CLASS_LINES_HIGH:
                    csev = "high"
                elif cls["line_count"] >= _CLASS_LINES_MEDIUM:
                    csev = "medium"
                else:
                    csev = None
                if csev:
                    sid = self.make_finding_id(rel, cls["name"], "large_class")
                    eid = self.make_entity_id(rel, "class", cls["name"])
                    _end = cls["lineno"] + cls["line_count"] - 1
                    smells.append(CodeSmell(
                        id=sid, type="large_class", severity=csev,
                        title="Large Class Detected",
                        file=rel, symbol=cls["name"], line=cls["lineno"],
                        end_line=_end,
                        snippet=extract_snippet(src, cls["lineno"], _end),
                        entity_id=eid,
                        kind="maintainability",
                        evidence=[Evidence(type="line_count", value=cls["line_count"],
                                           threshold=_CLASS_LINES_MEDIUM)],
                    ))

                # God object
                mc = cls["method_count"]
                if mc >= _GOD_METHODS_HIGH:
                    gsev = "high"
                elif mc >= _GOD_METHODS_MEDIUM:
                    gsev = "medium"
                else:
                    gsev = None
                if gsev:
                    sid = self.make_finding_id(rel, cls["name"], "god_object")
                    eid = self.make_entity_id(rel, "class", cls["name"])
                    smells.append(CodeSmell(
                        id=sid, type="god_object", severity=gsev,
                        title="God Object / Class Too Large",
                        file=rel, symbol=cls["name"], line=cls["lineno"],
                        snippet=extract_snippet(src, cls["lineno"]),
                        entity_id=eid,
                        kind="maintainability",
                        evidence=[Evidence(type="method_count", value=mc,
                                           threshold=_GOD_METHODS_MEDIUM)],
                    ))

            # --- AST-based security checks ----------------------------------
            _check_dangerous_calls(src, tree, rel, sec_findings)

        logger.info(
            "AST scan complete: %d function(s), %d class(es), %d import(s), "
            "%d TODO(s), %d security finding(s)",
            len(all_funcs), len(all_classes), len(all_imports),
            todo_count, len(sec_findings),
        )
        # --- pylint integration ------------------------------------------
        logger.info("Running pylint on %d file(s)…", min(len(source_files), 50))
        _src_cache: dict[str, str] = {}

        def _read_src(rp: str) -> str:
            if rp not in _src_cache:
                try:
                    _src_cache[rp] = (self.repo_path / rp).read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    _src_cache[rp] = ""
            return _src_cache[rp]

        for msg in _run_pylint(self.repo_path, source_files):
            sym = msg.get("symbol", "")
            if sym not in _PYLINT_SYMBOL_MAP:
                continue
            ftype, sev = _PYLINT_SYMBOL_MAP[sym]
            rel_path = _make_relative(msg.get("path", ""), self.repo_path)
            lineno = msg.get("line", 0)
            obj = msg.get("obj", "")
            fid = self.make_finding_id(rel_path, obj, ftype)
            eid = self.make_entity_id(rel_path, "function", obj) if obj else self.make_entity_id(rel_path, "file", rel_path)
            _kind = _PYLINT_TYPE_KIND.get(ftype, "maintainability")
            _file_src = _read_src(rel_path)
            findings.append(Finding(
                id=fid, type=ftype, severity=sev,
                title=msg.get("message", sym),
                file=rel_path, symbol=obj, line=lineno,
                entity_id=eid,
                kind=_kind,
                snippet=extract_snippet(_file_src, lineno),
            ))

        # --- import graph & circular deps --------------------------------
        logger.info("Building Python import graph…")
        # circular_deps stored on self._circular_deps for core.py to read
        self._circular_deps = self._build_import_graph(all_imports, source_files)
        logger.debug(
            "Import graph: %d edge(s), %d cycle(s)",
            len(self._import_edges), len(self._circular_deps),
        )

        # --- build audit objects -----------------------------------------
        # Derive file-level import context from collected data
        file_modules: dict[str, list[str]] = {}
        for imp in all_imports:
            file_modules.setdefault(imp["file"], []).append(imp["module"])

        file_callees: dict[str, list[str]] = {}
        file_callers: dict[str, list[str]] = {}
        for src, tgt in self._import_edges:
            file_callees.setdefault(src, []).append(tgt)
            file_callers.setdefault(tgt, []).append(src)

        audit_objects: list[AuditObject] = []
        for fn in all_funcs:
            rel_f = fn["file"]
            eid = self.make_entity_id(rel_f, "function", fn["name"])
            ctx = AuditContext(
                imports=sorted(set(file_modules.get(rel_f, []))),
                callers=sorted(set(file_callers.get(rel_f, []))),
                callees=sorted(set(file_callees.get(rel_f, []))),
            )
            audit_objects.append(AuditObject(
                entity_id=eid, kind="function",
                name=fn["name"], file=rel_f,
                confidence=1.0, context=ctx,
            ))
        for cls in all_classes:
            rel_f = cls.get("file", "")
            eid = self.make_entity_id(rel_f, "class", cls["name"])
            ctx = AuditContext(
                imports=sorted(set(file_modules.get(rel_f, []))),
                callers=sorted(set(file_callers.get(rel_f, []))),
                callees=sorted(set(file_callees.get(rel_f, []))),
            )
            audit_objects.append(AuditObject(
                entity_id=eid, kind="class",
                name=cls["name"], file=rel_f,
                confidence=1.0, context=ctx,
            ))
        logger.debug("Built %d audit object(s)", len(audit_objects))

        # --- dependency analysis -----------------------------------------
        logger.info("Analyzing Python dependencies…")
        declared, outdated, unused = self._analyze_dependencies(all_imports)
        logger.info(
            "Dependencies: %d declared, %d unused, %d outdated",
            len(declared), len(unused), len(outdated),
        )

        # --- metrics -------------------------------------------------------
        func_lengths = [f["line_count"] for f in all_funcs]
        avg_len = round(sum(func_lengths) / len(func_lengths), 1) if func_lengths else 0.0
        high_cx = sum(
            1 for f in all_funcs if f.get("complexity", 0) >= _COMPLEXITY_MEDIUM
        )
        test_coverage = _estimate_test_coverage(source_files, test_files, all_funcs)

        # --- security counts ---------------------------------------------
        # (counts are computed in to_dict from findings with kind="security")

        return AnalysisResult(
            metrics=MetricsInfo(
                total_functions=len(all_funcs),
                avg_function_length=avg_len,
                high_complexity_functions=high_cx,
                test_coverage_estimate=test_coverage,
                todo_count=todo_count,
            ),
            findings=findings + sec_findings,
            code_smells=smells,
            architecture=ArchitectureInfo(),
            dependencies=DependenciesInfo(
                outdated_packages=outdated,
                unused_dependencies=unused,  # list[str]; core will score & wrap
            ),
            audit_objects=audit_objects,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _collect_files(self) -> list[str]:
        result: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self.repo_path):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in IGNORE_DIRS and not d.startswith(".")
            )
            for name in sorted(filenames):
                if name.endswith(".py"):
                    rel = Path(dirpath, name).relative_to(self.repo_path).as_posix()
                    result.append(rel)
        return result

    def _build_import_graph(
        self, all_imports: list[dict], source_files: list[str]
    ) -> list[list[str]]:
        """Build internal import graph, store edges, return circular deps."""
        # Map module path → relative file path
        mod_to_file: dict[str, str] = {}
        for f in source_files:
            mod = f.removesuffix(".py").replace("/", ".").replace("\\", ".")
            if mod.endswith(".__init__"):
                mod = mod[: -9]
            mod_to_file[mod] = f
            # Also register base name for non-packaged imports
            base = mod.split(".")[-1]
            mod_to_file.setdefault(base, f)

        g = nx.DiGraph()
        g.add_nodes_from(source_files)

        for imp in all_imports:
            from_file = imp["file"]
            mod_name = imp["module"]

            if imp["level"] > 0:
                # Relative import: resolve relative to current package
                parts = from_file.split("/")
                pkg = "/".join(parts[: -(imp["level"])])
                if mod_name:
                    candidate = (pkg + "/" + mod_name.replace(".", "/") + ".py").lstrip("/")
                else:
                    candidate = pkg + "/__init__.py"
                if candidate in set(source_files):
                    self._import_edges.append((from_file, candidate))
                    g.add_edge(from_file, candidate)
            else:
                # Absolute import
                to_file = mod_to_file.get(mod_name)
                if to_file and to_file != from_file:
                    self._import_edges.append((from_file, to_file))
                    g.add_edge(from_file, to_file)

        cycles = [sorted(c) for c in nx.simple_cycles(g)]
        return sorted(cycles)

    def _analyze_dependencies(
        self, all_imports: list[dict]
    ) -> tuple[dict[str, str], list[OutdatedPackage], list[str]]:
        """Parse manifests, detect unused deps, check for outdated packages."""
        declared: dict[str, str] = {}

        req_txt = self.repo_path / "requirements.txt"
        if req_txt.exists():
            declared.update(_parse_requirements_txt(req_txt))
            logger.debug("Parsed requirements.txt: %d package(s)", len(declared))

        pyproject = self.repo_path / "pyproject.toml"
        if pyproject.exists():
            declared.update(_parse_pyproject_toml(pyproject))
            logger.debug("Parsed pyproject.toml: %d package(s) total", len(declared))

        # Actual top-level imports used in the codebase
        used_modules: set[str] = {
            imp["module"].split(".")[0].lower()
            for imp in all_imports
            if imp["level"] == 0 and imp["module"]
        }

        # Unused: declared but never imported
        unused = sorted(
            name for name in declared if name not in used_modules
        )

        # Outdated: fetch latest from PyPI
        if declared:
            logger.info("Checking PyPI for outdated packages (%d)…", len(declared))
        outdated: list[OutdatedPackage] = []
        for name, spec in declared.items():
            current_ver = _extract_version(spec)
            if not current_ver:
                continue
            latest = _fetch_pypi_latest(name)
            if latest and _is_outdated(current_ver, latest):
                outdated.append(OutdatedPackage(
                    name=name, current=current_ver, recommended=latest
                ))

        logger.debug(
            "Python deps result: %d declared, %d unused, %d outdated",
            len(declared), len(unused), len(outdated),
        )
        return declared, sorted(outdated, key=lambda p: p.name), unused


# ---------------------------------------------------------------------------
# Module-level AST collection helpers
# ---------------------------------------------------------------------------

def _collect_ast(
    src: str, tree: ast.Module, rel: str
) -> tuple[list[dict], list[dict], list[dict]]:
    funcs:   list[dict] = []
    classes: list[dict] = []
    imports: list[dict] = []

    class _Visitor(ast.NodeVisitor):
        def __init__(self):
            self._class_stack: list[str] = []

        def visit_ClassDef(self, node: ast.ClassDef):
            methods = [
                n for n in ast.walk(node)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n is not node
            ]
            # Only count direct methods (depth 1 inside the class)
            direct_methods = [
                n for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            classes.append({
                "name": node.name,
                "lineno": node.lineno,
                "line_count": (node.end_lineno or node.lineno) - node.lineno + 1,
                "method_count": len(direct_methods),
                "file": rel,
            })
            self._class_stack.append(node.name)
            self.generic_visit(node)
            self._class_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef):
            qual = (
                ".".join(self._class_stack) + "." + node.name
                if self._class_stack else node.name
            )
            all_args = (
                node.args.args
                + node.args.posonlyargs
                + node.args.kwonlyargs
            )
            # Remove 'self' / 'cls' from methods
            if self._class_stack and all_args and all_args[0].arg in ("self", "cls"):
                all_args = all_args[1:]
            funcs.append({
                "name": qual,
                "lineno": node.lineno,
                "line_count": (node.end_lineno or node.lineno) - node.lineno + 1,
                "param_count": len(all_args),
                "file": rel,
                "_node": node,
            })
            self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

        def visit_Import(self, node: ast.Import):
            for alias in node.names:
                imports.append({
                    "file": rel, "module": alias.name,
                    "level": 0, "lineno": node.lineno,
                })

        def visit_ImportFrom(self, node: ast.ImportFrom):
            imports.append({
                "file": rel,
                "module": node.module or "",
                "level": node.level or 0,
                "lineno": node.lineno,
            })

    _Visitor().visit(tree)
    return funcs, classes, imports


def _check_dangerous_calls(
    src: str, tree: ast.Module, rel: str,
    sec_findings: list[Finding],
) -> None:
    """AST-based detection of dangerous Python calls."""
    _file_eid = "ENTT-" + hashlib.sha256(f"{rel}\x00file\x00{rel}".encode()).hexdigest()[:8].upper()

    class _SecVisitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            func = node.func
            # eval / exec / compile
            if isinstance(func, ast.Name) and func.id in {"eval", "exec", "compile"}:
                ftype = f"{func.id}_usage"
                _key = f"{rel}\x00{node.lineno}\x00{ftype}"
                fid = "FIND-" + hashlib.sha256(_key.encode()).hexdigest()[:8].upper()
                sec_findings.append(Finding(
                    id=fid, type=ftype, file=rel,
                    line=node.lineno, severity="high",
                    title=f"Direct call to {func.id}()", kind="security",
                    entity_id=_file_eid,
                    snippet=extract_snippet(src, node.lineno),
                ))
            # os.system / os.popen
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
                and func.attr in {"system", "popen"}
            ):
                ftype = "os_shell_call"
                _key = f"{rel}\x00{node.lineno}\x00{ftype}"
                fid = "FIND-" + hashlib.sha256(_key.encode()).hexdigest()[:8].upper()
                sec_findings.append(Finding(
                    id=fid, type=ftype, file=rel,
                    line=node.lineno, severity="medium",
                    title=f"os.{func.attr}() call", kind="security",
                    entity_id=_file_eid,
                    snippet=extract_snippet(src, node.lineno),
                ))
            # subprocess.run / Popen with shell=True
            if isinstance(func, ast.Attribute) and func.attr in {"run", "Popen", "call"}:
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        ftype = "subprocess_shell_true"
                        _key = f"{rel}\x00{node.lineno}\x00{ftype}"
                        fid = "FIND-" + hashlib.sha256(_key.encode()).hexdigest()[:8].upper()
                        sec_findings.append(Finding(
                            id=fid, type=ftype, file=rel,
                            line=node.lineno, severity="medium",
                            title="subprocess called with shell=True", kind="security",
                            entity_id=_file_eid,
                            snippet=extract_snippet(src, node.lineno),
                        ))
            # pickle.loads / pickle.load
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "pickle"
                and func.attr in {"loads", "load"}
            ):
                ftype = "unsafe_deserialization"
                _key = f"{rel}\x00{node.lineno}\x00{ftype}"
                fid = "FIND-" + hashlib.sha256(_key.encode()).hexdigest()[:8].upper()
                sec_findings.append(Finding(
                    id=fid, type=ftype, file=rel,
                    line=node.lineno, severity="medium",
                    title="pickle.loads() — arbitrary code execution risk", kind="security",
                    entity_id=_file_eid,
                    snippet=extract_snippet(src, node.lineno),
                ))
            self.generic_visit(node)

    _SecVisitor().visit(tree)


# ---------------------------------------------------------------------------
# Minor utilities
# ---------------------------------------------------------------------------

def _is_test_file(rel: str) -> bool:
    name = Path(rel).name
    return name.startswith("test_") or name.endswith("_test.py") or "/tests/" in rel or "/test/" in rel


def _estimate_test_coverage(
    src_files: list[str], test_files: list[str], all_funcs: list[dict]
) -> float:
    """Very rough estimate: ratio of test files to source files, capped at 100."""
    if not src_files:
        return 0.0
    ratio = len(test_files) / len(src_files)
    return round(min(ratio * 100, 100.0), 1)


def _make_relative(abs_path: str, repo_root: Path) -> str:
    try:
        return Path(abs_path).relative_to(repo_root).as_posix()
    except ValueError:
        return abs_path


def _extract_version(spec: str) -> str | None:
    """Extract a plain version string from a PEP 440 specifier like '==1.2.3'."""
    m = re.search(r"==\s*([^\s,;]+)", spec)
    return m.group(1) if m else None


def _is_outdated(current: str, latest: str) -> bool:
    try:
        from packaging.version import Version
        return Version(current) < Version(latest)
    except Exception:
        return False
