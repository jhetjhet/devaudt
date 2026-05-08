"""
analyzer/scoring.py — Deterministic severity and confidence scoring.

All functions are pure and side-effect free so results are reproducible
across runs for the same repo and commit.

Severity scale: 0.0 – 10.0  (float, two decimal places in output)
Confidence:     0.0 – 1.0   (float, two decimal places in output)
"""
from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Severity: label → numeric (0–10)
# ---------------------------------------------------------------------------

_SEVERITY_NUMERIC: dict[str, float] = {
    "critical": 10.0,
    "high":      7.5,
    "medium":    5.0,
    "low":       2.5,
    "info":      1.0,
}

# Base severity values derived purely from evidence thresholds.
# Each finding type has a (low_threshold, medium_threshold, high_threshold, max_severity).
_TYPE_SEVERITY: dict[str, tuple[float, float, float, float]] = {
    # type                     low    med    high   max_sev
    "large_function":         (50,   150,   300,   8.0),
    "high_complexity":        (10,    15,    25,   9.0),
    "deep_nesting":           ( 4,     6,     8,   6.0),
    "long_parameter_list":    ( 5,     8,    12,   5.0),
    "large_class":            (200,  500,  1000,   7.0),
    "god_object":             (15,    20,    30,   7.5),
    "hardcoded_secret":       ( 0,     0,     0,  10.0),
    "hardcoded_password":     ( 0,     0,     0,   9.5),
    "hardcoded_private_key":  ( 0,     0,     0,  10.0),
    "hardcoded_db_password":  ( 0,     0,     0,   9.5),
    "eval_usage":             ( 0,     0,     0,   9.0),
    "eval-used":              ( 0,     0,     0,   9.0),
    "exec-used":              ( 0,     0,     0,   9.0),
    "os_shell_call":          ( 0,     0,     0,   7.0),
    "subprocess_shell_true":  ( 0,     0,     0,   7.0),
    "unsafe_deserialization": ( 0,     0,     0,   8.0),
    "innerHTML_assignment":   ( 0,     0,     0,   7.0),
    "document_write":         ( 0,     0,     0,   6.5),
    "new_function":           ( 0,     0,     0,   8.0),
    "bare_except":            ( 0,     0,     0,   3.5),
    "broad_exception":        ( 0,     0,     0,   3.0),
    "dangerous_default":      ( 0,     0,     0,   4.5),
    "unchecked_subprocess":   ( 0,     0,     0,   3.5),
}

# Base confidence per detection method.
_TYPE_CONFIDENCE_BASE: dict[str, float] = {
    # AST-derived — highest certainty
    "large_function":         0.95,
    "high_complexity":        0.92,
    "deep_nesting":           0.93,
    "long_parameter_list":    0.97,
    "large_class":            0.95,
    "god_object":             0.90,
    # Regex-derived secrets — medium certainty (false positives possible)
    "hardcoded_secret":       0.75,
    "hardcoded_password":     0.70,
    "hardcoded_private_key":  0.80,
    "hardcoded_db_password":  0.72,
    # AST-derived dangerous calls — very high certainty
    "eval_usage":             0.98,
    "eval-used":              0.98,
    "exec-used":              0.98,
    "os_shell_call":          0.95,
    "subprocess_shell_true":  0.95,
    "unsafe_deserialization": 0.95,
    "innerHTML_assignment":   0.88,
    "document_write":         0.90,
    "new_function":           0.88,
    # Lint rules — high certainty but may be intentional
    "bare_except":            0.85,
    "broad_exception":        0.82,
    "dangerous_default":      0.90,
    "unchecked_subprocess":   0.80,
}


def severity_numeric(
    label: str,
    finding_type: str = "",
    primary_value: float = 0.0,
) -> float:
    """
    Return a numeric severity in [0, 10].

    When a finding_type + primary_value are supplied the score is computed
    from the evidence thresholds of that type (more precise).
    Otherwise the label is mapped directly.
    """
    if finding_type in _TYPE_SEVERITY and primary_value > 0:
        low_th, med_th, high_th, max_sev = _TYPE_SEVERITY[finding_type]
        if high_th and primary_value >= high_th:
            ratio = min(primary_value / high_th, 3.0)
            return round(min(max_sev, max_sev * 0.9 + (max_sev * 0.1 * (ratio - 1))), 2)
        if med_th and primary_value >= med_th:
            t = (primary_value - med_th) / max(high_th - med_th, 1)
            base = max_sev * 0.6
            return round(base + (max_sev * 0.3 * min(t, 1.0)), 2)
        if low_th and primary_value >= low_th:
            t = (primary_value - low_th) / max(med_th - low_th, 1)
            return round(max_sev * 0.4 * min(t + 0.2, 1.0), 2)
        return round(max_sev * 0.2, 2)

    return _SEVERITY_NUMERIC.get(label.lower(), 2.5)


def confidence_numeric(
    finding_type: str,
    evidence_count: int = 1,
) -> float:
    """
    Return a confidence value in [0.0, 1.0].

    Evidence count provides a small boost (each extra piece adds 0.01,
    capped so the result never exceeds 0.99).
    """
    base = _TYPE_CONFIDENCE_BASE.get(finding_type, 0.65)
    boost = (evidence_count - 1) * 0.01
    return round(min(base + boost, 0.99), 2)


# ---------------------------------------------------------------------------
# Unused dependency confidence
# ---------------------------------------------------------------------------

# Dynamic loading patterns (Python + JS/TS)
_DYNAMIC_MARKERS_RE = re.compile(
    r"(__import__|importlib\.import_module"
    r"|require\s*\(\s*[a-zA-Z_\$]"
    r"|import\s*\(\s*[a-zA-Z_\$\`]"
    r"|getattr\s*\(\s*[^,]+,\s*[\"']"
    r"|plugin_class\s*=)",
    re.MULTILINE,
)

_INSTALLED_APPS_RE = re.compile(
    r"INSTALLED_APPS\s*[=\+]=?\s*\[([^\]]+)\]", re.DOTALL
)
_MIDDLEWARE_RE = re.compile(
    r"MIDDLEWARE\s*[=\+]=?\s*\[([^\]]+)\]", re.DOTALL
)
_ENTRY_POINTS_RE = re.compile(
    r"entry[_-]?points\s*[=:]\s*[\{\[](.+?)[\}\]]", re.DOTALL
)


def _scan_repo_text(repo_path: Path) -> tuple[bool, set[str], set[str]]:
    """
    Scan repository text files for:
      - has_dynamic   : whether any dynamic import pattern is found
      - django_names  : package roots that appear in INSTALLED_APPS / MIDDLEWARE
      - entry_points  : package names in entry_point declarations
    """
    has_dynamic = False
    django_names: set[str] = set()
    entry_point_names: set[str] = set()

    text_extensions = {
        ".py", ".txt", ".cfg", ".toml", ".ini", ".js", ".ts",
        ".jsx", ".tsx", ".json", ".yaml", ".yml",
    }

    for dirpath, dirnames, filenames in __import__("os").walk(repo_path):
        # Prune heavy dirs
        dirnames[:] = [
            d for d in sorted(dirnames)
            if d not in {
                "node_modules", ".git", ".venv", "venv", "env",
                "__pycache__", "dist", "build", ".next",
            }
        ]
        for fname in sorted(filenames):
            if Path(fname).suffix not in text_extensions:
                continue
            abs_file = Path(dirpath) / fname
            try:
                text = abs_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if not has_dynamic and _DYNAMIC_MARKERS_RE.search(text):
                has_dynamic = True

            # Django INSTALLED_APPS
            for m in _INSTALLED_APPS_RE.finditer(text):
                for app in re.findall(r"[\"']([A-Za-z0-9_\.]+)[\"']", m.group(1)):
                    root = app.split(".")[0].lower().replace("-", "_")
                    django_names.add(root)

            # MIDDLEWARE
            for m in _MIDDLEWARE_RE.finditer(text):
                for mw in re.findall(r"[\"']([A-Za-z0-9_\.]+)[\"']", m.group(1)):
                    root = mw.split(".")[0].lower().replace("-", "_")
                    django_names.add(root)

            # Entry points
            for m in _ENTRY_POINTS_RE.finditer(text):
                for ep in re.findall(r"[\"']([A-Za-z0-9_\-\.]+)[\"']", m.group(1)):
                    entry_point_names.add(ep.split(".")[0].lower().replace("-", "_"))

    return has_dynamic, django_names, entry_point_names


def _normalise_pkg(name: str) -> str:
    """Canonical comparison form: lower, dashes → underscores."""
    return name.lower().replace("-", "_")


def score_unused_dependency(
    name: str,
    *,
    used_modules: set[str],
    has_dynamic: bool,
    django_names: set[str],
    entry_point_names: set[str],
) -> tuple[float, list[str]]:
    """
    Return (confidence, reasons) for an unused dependency.

    confidence: 0.0–1.0
      0.0 = actually used (should not appear in unused list)
      1.0 = certainly unused
    """
    norm = _normalise_pkg(name)
    reasons: list[str] = []

    # Static import found — not unused
    if norm in {_normalise_pkg(u) for u in used_modules}:
        return 0.0, ["found_in_static_imports"]

    if norm in {_normalise_pkg(e) for e in entry_point_names}:
        reasons.append("declared_in_entry_points")
        return 0.10, reasons

    if norm in {_normalise_pkg(d) for d in django_names}:
        reasons.append("referenced_in_django_settings")
        return 0.20, reasons

    # Common packages known to be loaded via settings / plugin mechanisms
    _IMPLICIT_LOADERS = {
        "djangorestframework": "django_rest_framework_installed_apps",
        "rest_framework":      "django_rest_framework_installed_apps",
        "corsheaders":         "django_cors_headers_middleware",
        "django_cors_headers": "django_cors_headers_middleware",
        "storages":            "django_storages_backend",
        "django_storages":     "django_storages_backend",
        "djoser":              "djoser_installed_apps",
        "celery":              "celery_configured_in_settings",
        "channels":            "django_channels_installed_apps",
        "silk":                "django_silk_installed_apps",
        "debug_toolbar":       "django_debug_toolbar_installed_apps",
        "gunicorn":            "wsgi_server_runtime",
        "uvicorn":             "asgi_server_runtime",
        "whitenoise":          "wsgi_middleware_static_files",
        "psycopg2":            "database_driver_runtime",
        "mysqlclient":         "database_driver_runtime",
        "pymysql":             "database_driver_runtime",
    }
    if norm in _IMPLICIT_LOADERS:
        reasons.append(_IMPLICIT_LOADERS[norm])
        return 0.15, reasons

    if has_dynamic:
        reasons.append("project_uses_dynamic_loading")
        return 0.50, reasons

    reasons.append("no_static_import_found")
    return 1.0, reasons


def batch_unused_confidence(
    unused_names: list[str],
    used_modules: set[str],
    repo_path: Path,
) -> list[dict]:
    """
    Score all declared-but-not-imported package names.
    Returns a list of dicts with name/confidence/reasons, sorted by name.
    Only includes entries with confidence >= 0.40 (i.e., plausibly unused).
    """
    has_dynamic, django_names, entry_point_names = _scan_repo_text(repo_path)

    results = []
    for name in sorted(set(unused_names)):
        conf, reasons = score_unused_dependency(
            name,
            used_modules=used_modules,
            has_dynamic=has_dynamic,
            django_names=django_names,
            entry_point_names=entry_point_names,
        )
        if conf >= 0.40:
            results.append({
                "name": name,
                "confidence": round(conf, 2),
                "reasons": sorted(reasons),
            })

    return sorted(results, key=lambda x: x["name"])
