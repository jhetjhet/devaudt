from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from .models import ChangeSet

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IGNORE_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", ".venv", "venv", "env", ".env",
    "__pycache__", ".next", "dist", "build", ".cache",
    ".pytest_cache", "coverage", ".nyc_output", ".tox",
    ".eggs", ".mypy_cache", ".ruff_cache",
})

LANGUAGE_EXTENSIONS: dict[str, frozenset[str]] = {
    "python":     frozenset({".py"}),
    "typescript": frozenset({".ts", ".tsx"}),
    "javascript": frozenset({".js", ".jsx", ".mjs", ".cjs"}),
}

# package.json dep-name → canonical framework label
_PKG_FRAMEWORKS: dict[str, str] = {
    "next": "nextjs", "nuxt": "nuxt", "vite": "vite",
    "react": "react", "vue": "vue", "@angular/core": "angular",
    "svelte": "svelte", "express": "express", "fastify": "fastify",
    "@nestjs/core": "nestjs", "nestjs": "nestjs",
    "hapi": "hapi", "@hapi/hapi": "hapi",
    "gatsby": "gatsby", "remix": "remix",
    "@remix-run/node": "remix",
}

# Python import root → canonical framework label
_PY_FRAMEWORKS: dict[str, str] = {
    "fastapi": "fastapi", "django": "django", "flask": "flask",
    "tornado": "tornado", "starlette": "starlette", "aiohttp": "aiohttp",
    "sanic": "sanic", "litestar": "litestar",
}

# Directory names that imply a layered architecture
_LAYER_DIRS: frozenset[str] = frozenset({
    "controllers", "controller", "services", "service",
    "repositories", "repository", "repos", "models", "model",
    "routes", "route", "middleware", "handlers", "handler",
    "usecases", "use_cases", "domain", "infrastructure", "adapters",
})

# Top-level directories that are NOT services
_NON_SERVICE_DIRS: frozenset[str] = frozenset({
    "src", "lib", "tests", "test", "docs", "doc", "scripts", "script",
    "static", "public", "assets", "config", "configs", "utils", "helpers",
    "types", "styles", ".github", "bin", "tools",
})


class RepositoryScanner:
    """
    Scans a local repository for metadata, file lists, language/framework
    detection, architecture hints, and git history data.
    All file traversal is deterministic (sorted order).
    """

    def __init__(self, repo_path: str) -> None:
        self.root = Path(repo_path).resolve()

    # ------------------------------------------------------------------
    # Deterministic file traversal
    # ------------------------------------------------------------------

    def get_files(self, extensions: frozenset[str] | None = None) -> list[str]:
        """
        Return sorted POSIX repo-relative paths for all matching source files.
        Hidden directories and IGNORE_DIRS are pruned.
        """
        result: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in IGNORE_DIRS and not d.startswith(".")
            )
            for name in sorted(filenames):
                if extensions is None or Path(name).suffix in extensions:
                    rel = Path(dirpath, name).relative_to(self.root).as_posix()
                    result.append(rel)
        return result

    # ------------------------------------------------------------------
    # Git metadata
    # ------------------------------------------------------------------

    def _git(self, *args: str) -> str:
        try:
            out = subprocess.run(
                ["git", *args],
                capture_output=True, text=True, cwd=self.root, check=True,
            )
            return out.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return ""

    def get_commit_hash(self) -> str:
        return self._git("rev-parse", "HEAD")

    def get_branch(self) -> str:
        return self._git("rev-parse", "--abbrev-ref", "HEAD") or "HEAD"

    def get_change_set(self) -> ChangeSet:
        """Changes in the last commit (HEAD~1 diff); falls back to staged."""
        raw = self._git("diff", "--name-status", "HEAD~1")
        if not raw:
            raw = self._git("diff", "--name-status", "--cached")
        changed, added, deleted = [], [], []
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            status = parts[0][0]
            path = parts[-1]
            if status == "A":
                added.append(path)
            elif status == "D":
                deleted.append(path)
            else:
                changed.append(path)
        return ChangeSet(
            changed_files=sorted(changed),
            added_files=sorted(added),
            deleted_files=sorted(deleted),
        )

    # ------------------------------------------------------------------
    # Language & framework detection
    # ------------------------------------------------------------------

    def detect_languages(self, files: list[str]) -> list[str]:
        extensions = {Path(f).suffix for f in files}
        langs: list[str] = []
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            if extensions & exts:
                langs.append(lang)
        return sorted(set(langs))

    def detect_frameworks(self, files: list[str]) -> list[str]:
        file_set = set(files)
        frameworks: set[str] = set()

        # File-presence markers (e.g., next.config.js → nextjs)
        _file_markers: dict[str, str] = {
            "next.config.js": "nextjs", "next.config.ts": "nextjs",
            "next.config.mjs": "nextjs", "nuxt.config.js": "nuxt",
            "nuxt.config.ts": "nuxt", "manage.py": "django",
            "vite.config.js": "vite", "vite.config.ts": "vite",
        }
        for marker, fw in _file_markers.items():
            if any(f == marker or f.endswith("/" + marker) for f in file_set):
                frameworks.add(fw)

        # package.json dependency scan
        for pkg_path in (f for f in files if Path(f).name == "package.json"):
            try:
                with open(self.root / pkg_path, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                all_deps: dict = {}
                all_deps.update(data.get("dependencies", {}))
                all_deps.update(data.get("devDependencies", {}))
                for dep, fw in _PKG_FRAMEWORKS.items():
                    if dep in all_deps:
                        frameworks.add(fw)
            except Exception:
                pass

        # Python import-based detection (scan first 50 py files, first 4 KiB each)
        py_import_re = re.compile(r"^\s*(?:import|from)\s+(\w+)", re.MULTILINE)
        for py_path in (f for f in files if f.endswith(".py")):
            try:
                with open(self.root / py_path, encoding="utf-8", errors="replace") as fh:
                    head = fh.read(4096)
                for m in py_import_re.finditer(head):
                    fw = _PY_FRAMEWORKS.get(m.group(1))
                    if fw:
                        frameworks.add(fw)
            except Exception:
                pass

        return sorted(frameworks)

    # ------------------------------------------------------------------
    # Architecture hints
    # ------------------------------------------------------------------

    def detect_architecture_pattern(self, files: list[str]) -> str:
        all_dirs: set[str] = set()
        for f in files:
            for part in Path(f).parts[:-1]:
                all_dirs.add(part.lower())

        layer_hits = sum(1 for d in all_dirs if d in _LAYER_DIRS)
        if layer_hits >= 2:
            return "layered"

        top_level = {
            Path(f).parts[0]
            for f in files
            if len(Path(f).parts) > 1
        }
        service_like = {d for d in top_level if d.lower() not in _NON_SERVICE_DIRS}
        if len(service_like) >= 3:
            return "monorepo"

        return "monolithic"

    def detect_services(self, files: list[str]) -> list[str]:
        top_dirs = sorted({
            Path(f).parts[0]
            for f in files
            if len(Path(f).parts) > 1
        })
        return [d for d in top_dirs if d.lower() not in _NON_SERVICE_DIRS]
