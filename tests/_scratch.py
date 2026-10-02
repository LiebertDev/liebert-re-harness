"""Per-process scratch directories for tests that must write INSIDE the workspace.

``safe_path()`` refuses the OS temp dir, so these tests cannot use ``tmp_path``; they used to share a
fixed ``dataset/runtime/_test_*_scratch`` directory, which two pytest processes on one checkout would
create, fill and delete under each other. The directory now carries the process id and lives under
the gitignored ``.pytest_evidence_scratch/pid_<n>/`` root, the same root ``conftest`` already owns:
its session fixture removes this process's root at start and end and sweeps roots of dead processes.
"""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def process_scratch(name: str) -> Path:
    """The (not yet created) scratch directory ``name`` that belongs to this process only."""
    return REPO_ROOT / ".pytest_evidence_scratch" / f"pid_{os.getpid()}" / name
