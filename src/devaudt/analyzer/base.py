from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from pathlib import Path

from .models import AnalysisResult, EvidenceEntry


class BaseAnalyzer(ABC):
    """
    Abstract contract every language analyzer must fulfill.

    Each analyzer receives the repository root path, runs language-specific
    tooling, and returns a normalized AnalysisResult.  The base class provides
    stable content-addressed ID generation so finding and evidence IDs are
    reproducible across runs for the same repo and commit.
    """

    def __init__(self, repo_path: str) -> None:
        self.repo_path = Path(repo_path).resolve()
        # Shared evidence registry populated via make_evidence_id()
        self._evidence_index: dict[str, EvidenceEntry] = {}
        # Directed import edges (from_rel_file, to_rel_file) for coupling analysis
        self._import_edges: list[tuple[str, str]] = []
        # Circular dependency chains detected by this analyzer
        self._circular_deps: list[list[str]] = []

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def analyze(self) -> AnalysisResult:
        """Run the full analysis and return a normalized AnalysisResult."""

    @property
    @abstractmethod
    def supported_extensions(self) -> list[str]:
        """File-name extensions this analyzer handles."""

    # ------------------------------------------------------------------
    # Stable ID helpers
    # ------------------------------------------------------------------

    def make_finding_id(self, rel_file: str, symbol: str, finding_type: str) -> str:
        """Produce a stable, content-addressed finding ID."""
        key = f"{rel_file}\x00{symbol}\x00{finding_type}"
        return "FIND-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper()

    def make_evidence_id(
        self, rel_file: str, line: int, evidence_type: str
    ) -> str:
        """Produce a stable evidence ID and register it in the index."""
        key = f"{rel_file}\x00{line}\x00{evidence_type}"
        evid = "EVID-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper()
        if evid not in self._evidence_index:
            self._evidence_index[evid] = EvidenceEntry(
                file=rel_file, line=line, description=evidence_type
            )
        return evid

    def relative(self, abs_path: str) -> str:
        """Return a POSIX-style path relative to the repository root."""
        try:
            return Path(abs_path).relative_to(self.repo_path).as_posix()
        except ValueError:
            return abs_path
