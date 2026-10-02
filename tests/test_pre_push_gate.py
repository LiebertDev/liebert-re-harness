"""The managed pre-push gate must not wave through a masked failure."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("_pre_push_gate", ROOT / "scripts" / "pre_push_gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

# Built by concatenation so this file never prints the markers itself.
FATAL = "Windows fatal " + "exception: access " + "violation"


def _child(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_fatal_text_blocks_even_with_exit_zero(capsys):
    rc, hits = gate.run_pytest(_child(f"import sys; print({FATAL!r}, file=sys.stderr)"))
    assert rc == 0
    assert hits and hits[0].startswith("stderr line 1:")


def test_fatal_text_on_stdout_is_found_too():
    rc, hits = gate.run_pytest(_child(f"print({'Fatal Python ' + 'error: x'!r})"))
    assert rc == 0 and hits and hits[0].startswith("stdout line 1:")


def test_clean_output_has_no_findings():
    rc, hits = gate.run_pytest(_child("print('37 passed')"))
    assert rc == 0 and hits == []


def test_run_gate_returns_one_on_fatal_text_despite_exit_zero(monkeypatch):
    monkeypatch.setattr(gate, "run_pytest", lambda cmd: (0, [f"stderr line 3: {FATAL}"]))
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    assert gate.run_gate([["HEAD"]]) == 1


def test_run_gate_still_blocks_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(gate, "run_pytest", lambda cmd: (1, []))
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    assert gate.run_gate([["HEAD"]]) == 1


def test_hook_template_fails_loudly_instead_of_falling_back_to_path_python():
    hook = gate.HOOK_TEMPLATE
    assert "PY=python" not in hook
    assert "exit 1" in hook and "BLOCKED" in hook


def _dump(frame: str) -> str:
    return (f"{FATAL.split(':')[0]}: access " + "violation\n\nThread 0x1 (most recent call first):\n"
            '  File "threading.py", line 369 in wait\n\nCurrent thread 0x2 (most recent call first):\n'
            f"  File {frame}\n")


_MEM_MAP = '"C:/v/site-packages/unicorn/unicorn_py3/unicorn.py", line 831 in mem_map'
_EMU_START = '"C:/v/site-packages/unicorn/unicorn_py3/unicorn.py", line 9 in emu_start'


def test_every_dump_blocks_whatever_its_frame():
    """No allow-list: not even the once-measured unicorn mem_map dump is skipped."""
    mem_map, other = _dump(_MEM_MAP), _dump(_EMU_START)
    assert len(gate.fatal_findings(mem_map, "stderr")) == 1
    assert len(gate.fatal_findings(other, "stderr")) == 1
    assert len(gate.fatal_findings(mem_map * 3 + other, "stderr")) == 4
    assert gate.fatal_findings(FATAL + "\n", "stderr")           # no readable frame: blocks


def test_a_child_that_prints_the_mem_map_dump_is_blocked_end_to_end():
    dump = _dump(_MEM_MAP)
    rc, hits = gate.run_pytest(_child(f"import sys; sys.stderr.write({dump!r})"))
    assert rc == 0 and len(hits) == 1
