"""tools_lattice.py's own contract: input validation, structured errors,
and the three operations, independent of any specific benchmark fixture
(WNL-T2-082's real-fixture re-solve lives in
test_lattice_reduce_registered_tool.py)."""
from __future__ import annotations

import json
import unittest
from unittest import mock

import pytest

# importorskip skips only when mpmath is absent but lets a genuinely broken install
# (ImportError raised inside it) propagate; a bare checkout must skip, not fail.
mpmath = pytest.importorskip("mpmath")

import liebert_re.recover.lll_exact as lll_exact
import liebert_re.tools.lattice as tools_lattice
from liebert_re.tools.lattice import MAX_BASIS_ENTRY_BITS, MAX_DIMENSION, lattice_reduce


class ToolsLatticeContractTests(unittest.TestCase):
    def test_reduce_a_small_known_basis(self):
        # A trivially reducible basis: [[10, 1], [1, 10]] should reduce to
        # something with a short vector like [1, -1] or similar in span --
        # just check the operation succeeds and returns a same-rank,
        # same-dimension integer basis (the real correctness proof, against
        # a real cryptanalytic instance, is the WNL-T2-082 test).
        result = json.loads(lattice_reduce([[10, 1], [1, 10]], operation="reduce"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["reduced_basis"]), 2)
        self.assertEqual(len(result["reduced_basis"][0]), 2)
        for row in result["reduced_basis"]:
            for entry in row:
                self.assertIsInstance(entry, int)

    def test_is_reduced_operation(self):
        result = json.loads(lattice_reduce([[1, 0], [0, 1]], operation="is_reduced"))
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["is_reduced"])

    def test_reduce_and_enumerate_requires_max_norm_sq(self):
        result = json.loads(lattice_reduce([[1, 0], [0, 1]], operation="reduce_and_enumerate"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "MAX_NORM_SQ_REQUIRED_FOR_ENUMERATE")

    def test_reduce_and_enumerate_finds_short_vectors(self):
        result = json.loads(lattice_reduce([[2, 0], [0, 2]], operation="reduce_and_enumerate", max_norm_sq=4))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["enumeration_status"], "COMPLETE")
        self.assertGreater(len(result["short_vectors"]), 0)

    def test_unknown_operation_is_rejected(self):
        result = json.loads(lattice_reduce([[1, 0], [0, 1]], operation="not_a_real_op"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "UNKNOWN_OPERATION")

    def test_empty_basis_is_rejected(self):
        result = json.loads(lattice_reduce([], operation="reduce"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "INVALID_BASIS")

    def test_inconsistent_row_dimensions_are_rejected(self):
        result = json.loads(lattice_reduce([[1, 2], [3, 4, 5]], operation="reduce"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "INVALID_BASIS")

    def test_non_integer_entries_are_rejected(self):
        result = json.loads(lattice_reduce([[1.5, 2], [3, 4]], operation="reduce"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "INVALID_BASIS")

    def test_oversized_dimension_is_rejected(self):
        basis = [[1 if i == j else 0 for j in range(MAX_DIMENSION + 1)] for i in range(MAX_DIMENSION + 1)]
        result = json.loads(lattice_reduce(basis, operation="reduce"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "INVALID_BASIS")
        self.assertIn("MAX_DIMENSION", result["detail"])

    def test_oversized_entry_bit_length_is_rejected(self):
        huge = 1 << (MAX_BASIS_ENTRY_BITS + 8)
        result = json.loads(lattice_reduce([[huge, 0], [0, 1]], operation="reduce"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "INVALID_BASIS")
        self.assertIn("MAX_BASIS_ENTRY_BITS", result["detail"])


class ToolsLatticeMpmathFailClosedTests(unittest.TestCase):
    """When the optional 'mpmath' backend is absent, the mpmath-dependent
    operations must fail closed with a structured TOOL_MISSING result rather
    than raising (which, because tools_lattice is eager-imported at
    teacher.py startup, would otherwise crash the whole harness). The
    exact-Fraction 'is_reduced' operation must keep working. mpmath is
    installed in this environment, so absence is simulated by patching the
    _HAVE_MPMATH flag both modules read."""

    @pytest.mark.contract
    def test_reduce_reports_tool_missing_when_mpmath_absent(self):
        with mock.patch.object(tools_lattice, "_HAVE_MPMATH", False):
            result = json.loads(lattice_reduce([[10, 1], [1, 10]], operation="reduce"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "TOOL_MISSING")
        self.assertEqual(result["error"], "MPMATH_UNAVAILABLE")
        self.assertEqual(result["missing_dependency"], "mpmath")

    @pytest.mark.contract
    def test_reduce_and_enumerate_reports_tool_missing_when_mpmath_absent(self):
        with mock.patch.object(tools_lattice, "_HAVE_MPMATH", False):
            result = json.loads(lattice_reduce([[2, 0], [0, 2]], operation="reduce_and_enumerate", max_norm_sq=4))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "MPMATH_UNAVAILABLE")

    def test_is_reduced_still_works_without_mpmath(self):
        with mock.patch.object(tools_lattice, "_HAVE_MPMATH", False):
            result = json.loads(lattice_reduce([[1, 0], [0, 1]], operation="is_reduced"))
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["is_reduced"])

    def test_lll_reduce_raises_typed_error_when_mpmath_absent(self):
        # Defense in depth: a direct caller of the primitive (not through the
        # JSON tool wrapper) gets a typed LLLError, never a bare AttributeError
        # from mpmath being None.
        with mock.patch.object(lll_exact, "_HAVE_MPMATH", False):
            with self.assertRaises(lll_exact.LLLError) as ctx:
                lll_exact.lll_reduce([[10, 1], [1, 10]])
        self.assertIn("MPMATH_UNAVAILABLE", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
