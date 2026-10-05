"""``max_output_chars`` bounds the RESULT, not the memory read.

KNOWN, ACCEPTED LIMITATION, pinned here on purpose. ``run_bounded_process``
reads through ``Popen.communicate()``, which accumulates everything the child
writes and only then hands it to ``_limit_text``. A child emitting gigabytes
fills memory even with a small ``max_output_chars``. Bounding the read needs
reader threads or ``selectors`` (``selectors`` does not work on Windows
pipes); that was deliberately not done, because this module sits under every
tool wrapper and a half-built streaming reader is worse than the limitation.

If this test turns RED, someone made the limit bound the read. That is GOOD:
update the test to assert the new bound, do not delete it as "broken".

MEASURED PROXY: ``_limit_text`` is wrapped to record the length of the
stream it was handed, i.e. how much had already been accumulated before any
limit was applied.
"""
from __future__ import annotations

import sys
import unittest
from unittest import mock

import pytest

import liebert_re.bounded_subprocess as bounded_subprocess
from liebert_re.bounded_subprocess import run_bounded_process

_LIMIT = 1_000
_EMIT = 200_000


def _emitter(n: int) -> list[str]:
    return [sys.executable, "-c", f"import sys; sys.stdout.write('x' * {n})"]


def _run(n: int, limit: int):
    seen: list[int] = []
    real = bounded_subprocess._limit_text

    def spy(value, maximum):
        seen.append(len(value or ""))
        return real(value, maximum)

    with mock.patch.object(bounded_subprocess, "_limit_text", side_effect=spy):
        result = run_bounded_process(_emitter(n), timeout_seconds=30, max_output_chars=limit)
    return result, seen


class OutputLimitBoundsResultNotRead(unittest.TestCase):
    @pytest.mark.contract
    def test_max_output_chars_bounds_the_result_not_the_memory_read(self):
        result, seen = _run(_EMIT, _LIMIT)
        # Accumulated before limiting: far beyond the limit (the limitation).
        self.assertIn(_EMIT, seen)
        self.assertGreater(max(seen), _LIMIT * 100)
        # The result itself is bounded, and the truncation is reported.
        self.assertTrue(result.output_truncated)
        self.assertIn("[OUTPUT_TRUNCATED", result.stdout)
        self.assertLess(len(result.stdout), _EMIT)

    @pytest.mark.contract
    def test_output_under_the_limit_is_returned_complete_and_unflagged(self):
        result, seen = _run(_EMIT, _EMIT * 10)
        self.assertFalse(result.output_truncated)
        self.assertEqual(result.stdout, "x" * _EMIT)
        self.assertNotIn("[OUTPUT_TRUNCATED", result.stdout)
