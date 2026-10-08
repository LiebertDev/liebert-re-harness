"""`liebert_re.tools.ida` / `query_program.idapy`: the four queries added for the recurring gaps in
solved-case reports -- `read_bytes`, the name-resolving `xrefs_to`, `xrefs_from` and
`callers_of_import`.

Fast tier: nothing here starts IDA. The packaged worker is executed against stub `ida_*` modules
driven by a small in-memory database (`FakeDatabase`), and `ida_query` is exercised through the
same `FakeIdat` stand-in as `test_tools_ida.py`. The real-install checks of these queries live in
`IdaRealInstallTests` (heavy) in that file.

What the cases pin:

* `read_bytes` never turns a byte IDA holds no value for into a number: `bytes_hex` is null unless
  every byte is loaded, loaded runs and unloaded/unmapped runs are listed apart, and each bad
  request has its own error code (the wrapper refuses a bad size before IDA starts);
* `xrefs_to` says how a name was resolved (`resolved_by`), lists every candidate address and picks
  none, adds the import slot of an import of that name, and splits code from data by `kind`;
* `xrefs_from` scopes to a function or to one address, drops fall-through, reports `truncated`;
* `callers_of_import` lists function, address and call site, follows one level of thunk, and an
  unknown import is an error naming the import table, not an empty OK.

The second half of the file covers the ten read-only listing operations (`disasm_range`,
`basic_blocks`, `callgraph`, `stack_frame`, `local_variables`, `find_bytes`, `find_immediate`,
`list_structs`, `get_struct`, `flirt_signatures`): what is not an instruction is never disassembled,
indirect calls are counted and never resolved, a missing frame or decompiler is an error, every
listing is bounded and paged, the wrapper and the worker refuse the same requests, and the new
worker code calls nothing that writes.

The last section pins the difference between "not found" and "could not look": every answer carries
`status` (OK / NOT_FOUND / UNRESOLVED / QUERY_FAILED), `partial` and `lookup_errors`, an error inside a
lookup is never read as an empty result, an unknown bitfield flag is null, and the wrapper carries all of it
upward as `query_result` without touching its own run-level `status`.
"""
from __future__ import annotations

import ast
import json
import sys
from types import SimpleNamespace

import pytest

import liebert_re.tools.ida as ti
from tests.test_tools_ida import IdaCase, _load_worker

BADADDR = 0xFFFFFFFFFFFFFFFF
FUNC_THUNK = 0x80


def _xref(frm, to, type_, iscode):
    return SimpleNamespace(frm=frm, to=to, type=type_, iscode=iscode)


class FakeDatabase:
    """A few segments, names, imports, functions and references, wired into the worker's stubs."""

    def __init__(self):
        self.segments = {}      # name -> (start, end)
        self.loaded = {}        # ea -> byte value (absent = no value)
        self.names = {}         # name -> ea
        self.mangled = {}       # mangled name -> demangled text
        self.imports = []       # (module, name, ordinal, ea)
        self.functions = {}     # start -> (end, flags)
        self.refs_to = {}       # ea -> [xref]
        self.refs_from = {}     # ea -> [xref]
        self.mnemonics = {}
        self.import_enum_error = None

    def seg_of(self, ea):
        for name, (start, end) in self.segments.items():
            if start <= ea < end:
                return name, start, end
        return None

    def wire(self, ida):
        db = self
        idc, nalt, name, funcs, utils, seg, byt = (ida[n] for n in (
            "idc", "ida_nalt", "ida_name", "ida_funcs", "idautils", "ida_segment", "ida_bytes"))
        idc.BADADDR = BADADDR
        idc.get_name_ea_simple.side_effect = lambda n: db.names.get(n, BADADDR)
        idc.get_segm_name.side_effect = lambda ea: (db.seg_of(ea) or ("",))[0]
        idc.print_insn_mnem.side_effect = lambda ea: db.mnemonics.get(ea, "")
        ida["ida_xref"].fl_F = 21
        funcs.FUNC_THUNK = FUNC_THUNK

        def getseg(ea):
            found = db.seg_of(ea)
            return SimpleNamespace(start_ea=found[1], end_ea=found[2], perm=5) if found else None

        seg.getseg.side_effect = getseg
        seg.get_segm_name.side_effect = lambda s: db.seg_of(s.start_ea)[0]
        byt.is_loaded.side_effect = lambda ea: ea in db.loaded
        byt.get_byte.side_effect = lambda ea: db.loaded[ea]
        name.get_name.side_effect = lambda ea: next((n for n, e in db.names.items() if e == ea), "")
        name.MNG_SHORT_FORM, name.MNG_LONG_FORM = 1, 2
        name.demangle_name.side_effect = lambda m, form: db.mangled.get(m)
        utils.Names.side_effect = lambda: list((ea, n) for n, ea in db.names.items())

        def get_func(ea):
            for start, (end, flags) in db.functions.items():
                if start <= ea < end:
                    return SimpleNamespace(start_ea=start, end_ea=end, flags=flags)
            return None

        funcs.get_func.side_effect = get_func
        utils.FuncItems.side_effect = lambda start: iter(range(start, db.functions[start][0]))
        utils.XrefsTo.side_effect = lambda ea, flags=0: iter(db.refs_to.get(ea, []))
        utils.XrefsFrom.side_effect = lambda ea, flags=0: iter(db.refs_from.get(ea, []))
        utils.XrefTypeName.side_effect = lambda t: {16: "Code_Far_Call", 17: "Code_Near_Call", 19: "Code_Near_Jump",
                                                   21: "Ordinary_Flow", 1: "Data_Offset", 3: "Data_Read"}.get(t, f"t{t}")
        def modules():
            return sorted({m for m, *_ in db.imports})

        nalt.get_import_module_qty.side_effect = lambda: len(modules())
        nalt.get_import_module_name.side_effect = lambda i: modules()[i]

        def enum(index, callback):
            if db.import_enum_error:
                raise db.import_enum_error
            for module, n, ordinal, ea in db.imports:
                if module == modules()[index] and callback(ea, n, ordinal) is False:
                    return

        nalt.enum_import_names.side_effect = enum


@pytest.fixture
def worker():
    module, ida = _load_worker()
    db = FakeDatabase()
    db.segments = {".text": (0x1000, 0x2000), ".data": (0x3000, 0x3100), ".idata": (0x4000, 0x4100)}
    db.wire(ida)
    return module, ida, db


def _run(module, operation, query, max_results=200, offset=0):
    result = {"ok": True, "items": []}
    module._DISPATCH[operation](result, query, max_results, offset)
    return result


# ---------------------------------------------------------------------------
# read_bytes
# ---------------------------------------------------------------------------
def test_read_bytes_fully_loaded_gives_hex_and_the_segment(worker):
    module, _ida, db = worker
    db.loaded.update({0x1000 + i: 0x41 + i for i in range(4)})
    r = _run(module, "read_bytes", "0x1000 4")
    assert r["ok"] and r["fully_loaded"] and r["bytes_hex"] == "41424344"
    assert r["segment"] == {"name": ".text", "start": "0x1000", "end": "0x2000"}
    assert r["loaded_ranges"] == [{"address": "0x1000", "size": 4, "bytes_hex": "41424344"}]
    assert r["unloaded_ranges"] == [] and r["loaded_count"] == 4 and r["crosses_segment_boundary"] is False


def test_unloaded_bytes_are_null_not_zero(worker):
    """Rule 4: a byte IDA holds no value for is not a number. A real 0x00 stays a 0x00."""
    module, _ida, db = worker
    db.loaded.update({0x3000: 0x00, 0x3001: 0xAA, 0x3004: 0xBB})     # 0x3002 and 0x3003 have no value
    r = _run(module, "read_bytes", json.dumps({"address": "0x3000", "size": 5}))
    assert r["fully_loaded"] is False and r["bytes_hex"] is None
    assert r["loaded_ranges"] == [{"address": "0x3000", "size": 2, "bytes_hex": "00aa"},
                                  {"address": "0x3004", "size": 1, "bytes_hex": "bb"}]
    assert r["unloaded_ranges"] == [{"address": "0x3002", "size": 2, "state": "unloaded"}]
    assert r["loaded_count"] == 3


def test_a_range_running_out_of_the_segment_marks_the_rest_unmapped(worker):
    module, _ida, db = worker
    db.loaded.update({0x30FE: 1, 0x30FF: 2})
    r = _run(module, "read_bytes", "0x30fe 4")
    assert r["bytes_hex"] is None and r["crosses_segment_boundary"] is True
    assert r["loaded_ranges"] == [{"address": "0x30fe", "size": 2, "bytes_hex": "0102"}]
    assert r["unloaded_ranges"] == [{"address": "0x3100", "size": 2, "state": "unmapped"}]


def test_a_range_spanning_two_adjacent_segments_reads_through(worker):
    module, _ida, db = worker
    db.segments = {".a": (0x1000, 0x1002), ".b": (0x1002, 0x1004)}
    db.loaded.update({0x1000: 1, 0x1001: 2, 0x1002: 3, 0x1003: 4})
    r = _run(module, "read_bytes", "0x1000 4")
    assert r["bytes_hex"] == "01020304" and r["crosses_segment_boundary"] is True and r["segment"]["name"] == ".a"


@pytest.mark.parametrize("query, error", [
    ("0x10 4", "ADDRESS_NOT_MAPPED"),
    ("0x1000 0", "INVALID_SIZE"),
    ("0x1000 4097", "INVALID_SIZE"),
    ("0x1000 -1", "INVALID_SIZE"),
    ("0x1000 four", "INVALID_SIZE"),
    ("-5 4", "INVALID_ADDRESS"),
    ("zzz 4", "INVALID_ADDRESS"),
    ("0xffffffffffffffff 4", "INVALID_ADDRESS"),
    ("", "INVALID_READ_BYTES_REQUEST"),
    ("0x1000", "INVALID_READ_BYTES_REQUEST"),
    ("0x1000 4 5", "INVALID_READ_BYTES_REQUEST"),
    ("{not json", "INVALID_READ_BYTES_REQUEST"),
    ('{"address": "0x1000"}', "INVALID_READ_BYTES_REQUEST"),
    ('{"address": true, "size": 4}', "INVALID_READ_BYTES_REQUEST"),
])
def test_each_bad_read_bytes_request_has_its_own_error(worker, query, error):
    module, _ida, _db = worker
    r = _run(module, "read_bytes", query)
    assert (r["ok"], r["error"]) == (False, error)
    assert "bytes_hex" not in r


def test_the_maximum_size_is_accepted_and_integers_work_in_json(worker):
    module, _ida, db = worker
    db.segments = {".big": (0x10000, 0x20000)}
    db.loaded.update({0x10000 + i: i & 0xFF for i in range(4096)})
    r = _run(module, "read_bytes", json.dumps({"address": 0x10000, "size": 4096}))
    assert r["ok"] and r["size"] == 4096 and r["fully_loaded"] and len(r["bytes_hex"]) == 8192


@pytest.mark.contract
def test_wrapper_and_worker_agree_on_which_requests_are_bad(worker):
    """The wrapper refuses before IDA starts, the worker re-checks: the two grammars must not drift."""
    module, _ida, db = worker
    db.loaded.update({0x1000 + i: 7 for i in range(4096)})
    queries = ["0x1000 4", "0x1000,4", "4096", "0x1000 0", "0x1000 4097", "-5 4", "zzz 4", "", "{", "[]",
               '{"address": "0x1000", "size": 8}', '{"address": "0x1000", "size": "8"}',
               '{"address": 4096, "size": 4096}', '{"size": 4}', '{"address": null, "size": 4}',
               "0xffffffffffffffff 4"]
    for query in queries:
        worker_error = _run(module, "read_bytes", query).get("error")
        if worker_error == "ADDRESS_NOT_MAPPED":
            worker_error = None            # a mapping question only the engine can answer
        assert ti._read_bytes_request_problem(query) == worker_error, query


# ---------------------------------------------------------------------------
# xrefs_to
# ---------------------------------------------------------------------------
def test_exact_name_is_resolved_by_exact_name(worker):
    module, _ida, db = worker
    db.names["target"] = 0x1100
    db.functions[0x1000] = (0x1200, 0)
    db.refs_to[0x1100] = [_xref(0x1010, 0x1100, 17, True), _xref(0x1020, 0x1100, 3, False)]
    r = _run(module, "xrefs_to", "target")
    assert r["resolved_by"] == "exact_name" and r["resolved_address"] == "0x1100"
    assert r["ambiguous"] is False and r["candidate_count"] == 1
    assert [(i["kind"], i["is_call"], i["to"]) for i in r["items"]] == [("code", True, "0x1100"), ("data", False, "0x1100")]
    assert r["total_xref_count"] == 2 and r["next_offset"] is None and r["truncated"] is False


def test_demangled_name_is_tried_after_the_exact_name(worker):
    module, _ida, db = worker
    db.names["?Run@Worker@@QEAAXXZ"] = 0x1100
    db.mangled["?Run@Worker@@QEAAXXZ"] = "Worker::Run(void)"
    db.refs_to[0x1100] = [_xref(0x1010, 0x1100, 17, True)]
    r = _run(module, "xrefs_to", "Worker::Run(void)")
    assert r["resolved_by"] == "demangled_name" and r["candidates"][0]["name"] == "?Run@Worker@@QEAAXXZ"
    assert len(r["items"]) == 1


def test_an_import_name_resolves_through_the_import_table(worker):
    module, _ida, db = worker
    db.imports = [("KERNEL32", "CreateFileW", None, 0x4010)]
    db.refs_to[0x4010] = [_xref(0x1010, 0x4010, 3, False)]
    r = _run(module, "xrefs_to", "CreateFileW")
    assert r["resolved_by"] == "import_name"
    assert r["candidates"] == [{"address": "0x4010", "name": None, "resolved_by": "import_name",
                                "import_module": "KERNEL32", "import_ordinal": None}]
    assert r["items"][0]["kind"] == "data" and r["items"][0]["to"] == "0x4010"


def test_a_thunk_and_its_import_slot_are_both_listed_and_none_is_chosen(worker):
    module, _ida, db = worker
    db.names["CreateFileW"] = 0x1500                                  # the thunk carries the plain name
    db.imports = [("KERNEL32", "CreateFileW", None, 0x4010)]
    db.refs_to[0x1500] = [_xref(0x1010, 0x1500, 17, True)]
    db.refs_to[0x4010] = [_xref(0x1500, 0x4010, 3, False)]
    r = _run(module, "xrefs_to", "CreateFileW")
    assert r["ambiguous"] is True and r["resolved_by"] == "multiple" and r["resolved_address"] is None
    assert [(c["address"], c["resolved_by"]) for c in r["candidates"]] == [("0x1500", "exact_name"), ("0x4010", "import_name")]
    assert [(i["to"], i["from"]) for i in r["items"]] == [("0x1500", "0x1010"), ("0x4010", "0x1500")]


def test_the_same_import_name_in_two_modules_gives_two_candidates(worker):
    module, _ida, db = worker
    db.imports = [("A.dll", "Open", None, 0x4010), ("B.dll", "Open", None, 0x4020)]
    r = _run(module, "xrefs_to", "Open")
    assert [c["import_module"] for c in r["candidates"]] == ["A.dll", "B.dll"]
    assert r["ambiguous"] is True and r["items"] == []


def test_a_raw_address_is_used_as_it_is(worker):
    module, _ida, db = worker
    db.refs_to[0x1100] = [_xref(0x1010, 0x1100, 19, True)]
    r = _run(module, "xrefs_to", "0x1100")
    assert r["resolved_by"] == "address" and r["items"][0]["is_call"] is False      # a jump is not a call


def test_an_unresolvable_name_is_an_error_not_an_empty_ok(worker):
    module, _ida, _db = worker
    r = _run(module, "xrefs_to", "NoSuchThing")
    assert (r["ok"], r["error"]) == (False, "SYMBOL_NOT_FOUND")


def test_a_failed_import_lookup_is_reported_not_swallowed(worker):
    module, _ida, db = worker
    db.names["target"] = 0x1100
    db.imports = [("K", "x", None, 0x4010)]
    db.import_enum_error = RuntimeError("enum broke")
    r = _run(module, "xrefs_to", "target")
    assert r["ok"] and r["resolved_by"] == "exact_name"
    assert any("IMPORT_LOOKUP_FAILED" in e and "enum broke" in e for e in r["lookup_errors"])


def test_xrefs_to_pages_across_candidates(worker):
    module, _ida, db = worker
    db.names["t"] = 0x1100
    db.refs_to[0x1100] = [_xref(0x1000 + i, 0x1100, 17, True) for i in range(5)]
    r = _run(module, "xrefs_to", "t", max_results=2, offset=1)
    assert [i["from"] for i in r["items"]] == ["0x1001", "0x1002"]
    assert r["next_offset"] == 3 and r["truncated"] is True


# ---------------------------------------------------------------------------
# xrefs_from
# ---------------------------------------------------------------------------
def _function_with_refs(db):
    db.names["func"] = 0x1000
    db.functions[0x1000] = (0x1004, 0)
    db.refs_from[0x1000] = [_xref(0x1000, 0x1001, 21, True)]                          # fall-through only
    db.refs_from[0x1001] = [_xref(0x1001, 0x3000, 1, False), _xref(0x1001, 0x1001 + 1, 21, True)]
    db.refs_from[0x1002] = [_xref(0x1002, 0x4010, 17, True), _xref(0x1002, 0x4010, 3, False)]
    db.names["slot"] = 0x4010


def test_xrefs_from_a_function_covers_every_instruction_and_drops_fallthrough(worker):
    module, _ida, db = worker
    _function_with_refs(db)
    r = _run(module, "xrefs_from", "func")
    assert r["scope"] == "function" and r["resolved_address"] == "0x1000"
    assert [(i["from"], i["to"], i["kind"], i["is_call"]) for i in r["items"]] == [
        ("0x1001", "0x3000", "data", False), ("0x1002", "0x4010", "code", True), ("0x1002", "0x4010", "data", False)]
    assert r["items"][1]["to_name"] == "slot" and r["total_xref_count"] == 3 and r["truncated"] is False


def test_xrefs_from_inside_a_function_is_scoped_to_that_one_address(worker):
    module, _ida, db = worker
    _function_with_refs(db)
    r = _run(module, "xrefs_from", "0x1002")
    assert r["scope"] == "address" and [i["from"] for i in r["items"]] == ["0x1002", "0x1002"]


def test_xrefs_from_reports_truncation_and_resumes(worker):
    module, _ida, db = worker
    _function_with_refs(db)
    first = _run(module, "xrefs_from", "func", max_results=2)
    assert first["truncated"] is True and first["next_offset"] == 2 and first["total_xref_count"] == 3
    rest = _run(module, "xrefs_from", "func", max_results=2, offset=2)
    assert rest["truncated"] is False and rest["next_offset"] is None and len(rest["items"]) == 1


def test_xrefs_from_unknown_symbol_is_an_error(worker):
    module, _ida, _db = worker
    assert _run(module, "xrefs_from", "nope")["error"] == "SYMBOL_NOT_FOUND"


# ---------------------------------------------------------------------------
# callers_of_import
# ---------------------------------------------------------------------------
def _import_with_callers(db):
    db.imports = [("KERNEL32", "CreateFileW", None, 0x4010)]
    db.names.update({"caller_a": 0x1000, "caller_b": 0x1100, "thunk_cf": 0x1200, "outer": 0x1300})
    db.functions.update({0x1000: (0x1100, 0), 0x1100: (0x1200, 0), 0x1200: (0x1210, FUNC_THUNK), 0x1300: (0x1400, 0)})
    db.mnemonics.update({0x1010: "call", 0x1110: "mov", 0x1200: "jmp", 0x1320: "call"})
    db.refs_to[0x4010] = [_xref(0x1010, 0x4010, 3, False), _xref(0x1110, 0x4010, 3, False),
                          _xref(0x1200, 0x4010, 3, False), _xref(0x9999, 0x4010, 1, False)]
    db.refs_to[0x1200] = [_xref(0x1320, 0x1200, 17, True)]


def test_callers_are_listed_with_function_address_and_call_site(worker):
    module, _ida, db = worker
    _import_with_callers(db)
    r = _run(module, "callers_of_import", "CreateFileW")
    assert r["imports"] == [{"module": "KERNEL32", "name": "CreateFileW", "ordinal": None, "slot": "0x4010"}]
    rows = {i["call_site"]: i for i in r["items"]}
    assert rows["0x1010"]["function_name"] == "caller_a" and rows["0x1010"]["function_address"] == "0x1000"
    assert rows["0x1010"]["is_call"] is True and rows["0x1010"]["via_thunk"] is None
    assert rows["0x1110"]["is_call"] is False and rows["0x1110"]["mnemonic"] == "mov"       # a read, not a call
    assert rows["0x9999"]["function_name"] is None and rows["0x9999"]["function_address"] is None   # unknown stays null


def test_a_thunk_is_followed_one_level(worker):
    module, _ida, db = worker
    _import_with_callers(db)
    r = _run(module, "callers_of_import", "CreateFileW")
    via = [i for i in r["items"] if i["via_thunk"]]
    assert [(i["call_site"], i["function_name"], i["via_thunk"]["name"]) for i in via] == [("0x1320", "outer", "thunk_cf")]
    assert any(i["call_site"] == "0x1200" and i["via_thunk"] is None for i in r["items"])   # the thunk's own jump stays


def test_callers_are_sorted_by_call_site_and_paged(worker):
    module, _ida, db = worker
    _import_with_callers(db)
    first = _run(module, "callers_of_import", "CreateFileW", max_results=2)
    assert [i["call_site"] for i in first["items"]] == ["0x1010", "0x1110"]
    assert first["truncated"] is True and first["next_offset"] == 2 and first["total_caller_count"] == 5
    last = _run(module, "callers_of_import", "CreateFileW", max_results=10, offset=4)
    assert [i["call_site"] for i in last["items"]] == ["0x9999"] and last["next_offset"] is None


def test_an_import_nobody_references_is_an_ok_empty_list_that_states_its_scope(worker):
    module, _ida, db = worker
    db.imports = [("KERNEL32", "Sleep", None, 0x4020)]
    r = _run(module, "callers_of_import", "Sleep")
    assert r["ok"] and r["items"] == [] and r["total_caller_count"] == 0
    assert "not searched" in r["search_scope"]


def test_an_unknown_import_is_an_error_about_the_import_table(worker):
    module, _ida, db = worker
    db.imports = [("KERNEL32", "Sleep", None, 0x4020)]
    r = _run(module, "callers_of_import", "NoSuchImport")
    assert (r["ok"], r["error"]) == (False, "IMPORT_NOT_FOUND")
    assert "import table" in r["detail"]


def test_a_failed_import_enumeration_is_reported_for_callers(worker):
    module, _ida, db = worker
    db.imports = [("K", "x", None, 0x4020)]
    db.import_enum_error = RuntimeError("boom")
    r = _run(module, "callers_of_import", "x")
    assert r["error"] == "IMPORT_NOT_FOUND" and any("IMPORT_LOOKUP_FAILED" in e for e in r["lookup_errors"])


def test_the_new_operations_are_dispatched_and_listed(worker):
    module, _ida, _db = worker
    for operation in ("read_bytes", "xrefs_from", "callers_of_import"):
        assert operation in module._OPERATIONS and operation in module._DISPATCH
    assert set(ti._ALLOWED_OPERATIONS) <= set(module._OPERATIONS)


# ---------------------------------------------------------------------------
# through ida_query (FakeIdat)
# ---------------------------------------------------------------------------
class QueryWrapperTests(IdaCase):
    def test_a_bad_read_bytes_request_is_refused_before_idat_starts(self):
        for query, error in (("0x1000 0", "INVALID_SIZE"), ("0x1000 4097", "INVALID_SIZE"), ("", "INVALID_READ_BYTES_REQUEST"),
                             ("zz 4", "INVALID_ADDRESS")):
            data = self.q("read_bytes", query)
            self.assertEqual((data["ok"], data["status"], data["error"]), (False, "ANALYSIS_LIMITED", error), query)
        self.assertEqual(self.fake.calls, [])

    def test_the_new_operations_are_accepted_and_the_listing_ones_resume(self):
        for operation, query in (("xrefs_from", "start"), ("callers_of_import", "CreateFileW"), ("read_bytes", "0x1000 8")):
            data = self.q(operation, query)
            self.assertTrue(data["ok"], data)
            self.assertEqual(data["operation"], operation)
        self.assertIn("xrefs_from", ti._PAGED_OPERATIONS)
        self.assertIn("callers_of_import", ti._PAGED_OPERATIONS)

    def test_unknown_operation_still_lists_the_accepted_ones(self):
        data = self.q("write_bytes", "0x1000 4")
        self.assertEqual(data["error"], "UNKNOWN_OPERATION")
        self.assertIn("read_bytes", data["accepted"])

    def test_a_response_cut_to_max_chars_trims_read_ranges_and_says_so(self):
        runs = [{"address": hex(0x1000 + 2 * i), "size": 1, "bytes_hex": "aa"} for i in range(600)]
        self.fake.fields["read_bytes"] = dict(address="0x1000", size=1200, bytes_hex=None, loaded_ranges=runs,
                                              unloaded_ranges=[])
        data = self.q("read_bytes", "0x1000 1200", max_chars=4000)
        self.assertEqual(data["status"], "PARTIAL")
        self.assertTrue(data["truncated"])
        self.assertLess(len(data["loaded_ranges"]), 600)
        self.assertLessEqual(len(json.dumps(data)), 4200)


# ===========================================================================
# W2: the read-only listing operations (disasm_range, basic_blocks, callgraph, stack_frame,
# local_variables, find_bytes, find_immediate, list_structs, get_struct, flirt_signatures).
#
# The worker runs against the same stub modules; `CodeModel` adds decoded items (instructions, data,
# undefined bytes), `FakeTypes` the type library and frames, and the ida_gdl / ida_frame / ida_search /
# ida_typeinf modules the operations import when they run.
# ===========================================================================
OT_VOID, OT_REG, OT_MEM, OT_FAR, OT_NEAR, OT_IMM = 0, 1, 2, 6, 7, 5
FL_CF, FL_CN, FL_JF, FL_JN = 16, 17, 18, 19
FUNC_LIB = 0x4


class CodeModel:
    """Decoded items over a `FakeDatabase`: `add_insn` / `add_data` define them, any other byte of a segment
    is undefined. Wired into the worker's `ida_bytes`, `idc`, `idautils`, `idaapi` and segment stubs."""

    def __init__(self, db):
        self.db = db
        self.items = {}         # head ea -> dict(kind, size, ops, optypes, call, imms)
        self.segs = []          # (name, start, end); the same name may repeat

    def add_insn(self, ea, size, mnemonic, ops=(), optypes=None, call=False, data=None, imms=None):
        self.items[ea] = dict(kind="code", size=size, ops=list(ops), optypes=list(optypes or [OT_REG] * len(ops)),
                              call=call, imms=dict(imms or {}))
        self.db.mnemonics[ea] = mnemonic
        for i in range(size):
            self.db.loaded[ea + i] = (data[i] if data else (0x90 + i)) & 0xFF

    def add_data(self, ea, size, data=None):
        self.items[ea] = dict(kind="data", size=size, ops=[], optypes=[], call=False, imms={})
        for i in range(size):
            self.db.loaded[ea + i] = (data[i] if data else 0xAA) & 0xFF

    def head_of(self, ea):
        for head, item in self.items.items():
            if head <= ea < head + item["size"]:
                return head
        return None

    def seg_of(self, ea):
        for name, start, end in self.segs:
            if start <= ea < end:
                return name, start, end
        return None

    def wire(self, ida):
        m, db = self, self.db
        byt, idc, seg, utils, idaapi = (ida[n] for n in ("ida_bytes", "idc", "ida_segment", "idautils", "idaapi"))
        idc.o_void, idc.o_near, idc.o_far = OT_VOID, OT_NEAR, OT_FAR
        ida["ida_xref"].fl_CF, ida["ida_xref"].fl_CN = FL_CF, FL_CN
        ida["ida_xref"].fl_JF, ida["ida_xref"].fl_JN = FL_JF, FL_JN
        ida["ida_funcs"].FUNC_LIB = FUNC_LIB
        byt.get_flags.side_effect = lambda ea: ea
        byt.is_tail.side_effect = lambda f: m.head_of(f) not in (None, f)
        byt.is_code.side_effect = lambda f: m.items.get(f, {}).get("kind") == "code"
        byt.is_unknown.side_effect = lambda f: m.head_of(f) is None
        byt.get_item_head.side_effect = lambda ea: m.head_of(ea) if m.head_of(ea) is not None else ea
        byt.get_item_end.side_effect = lambda head: head + m.items[head]["size"]
        byt.get_item_size.side_effect = lambda ea: m.items[ea]["size"] if ea in m.items else 1

        def get_bytes(ea, count):
            try:
                return bytes(db.loaded[ea + i] for i in range(count))
            except KeyError:
                return None

        byt.get_bytes.side_effect = get_bytes

        def find_bytes(pattern, start, range_end=None):
            tokens = pattern.split()
            for ea in range(start, (range_end if range_end is not None else start + 1) - len(tokens) + 1):
                if all(t == "?" or db.loaded.get(ea + i) == int(t, 16) for i, t in enumerate(tokens)):
                    return ea
            return BADADDR

        byt.find_bytes.side_effect = find_bytes
        idc.get_operand_type.side_effect = lambda ea, n: (
            m.items[ea]["optypes"][n] if ea in m.items and n < len(m.items[ea]["optypes"]) else OT_VOID)
        idc.print_operand.side_effect = lambda ea, n: m.items[ea]["ops"][n]
        idc.get_segm_name.side_effect = lambda ea: (m.seg_of(ea) or ("",))[0]
        idaapi.is_call_insn.side_effect = lambda ea: bool(m.items.get(ea, {}).get("call"))
        seg.getseg.side_effect = lambda ea: (
            SimpleNamespace(start_ea=m.seg_of(ea)[1], end_ea=m.seg_of(ea)[2], perm=5) if m.seg_of(ea) else None)
        seg.get_segm_name.side_effect = lambda s: m.seg_of(s.start_ea)[0]
        utils.Segments.side_effect = lambda: iter([start for _name, start, _end in sorted(m.segs, key=lambda x: x[1])])
        utils.Functions.side_effect = lambda: iter(sorted(db.functions))
        utils.FuncItems.side_effect = lambda start: iter(sorted(h for h in m.items if start <= h < db.functions[start][0]))
        ida["ida_ida"].inf_get_min_ea.return_value = min(s for _n, s, _e in m.segs)
        ida["ida_ida"].inf_get_max_ea.return_value = max(e for _n, _s, e in m.segs)


class FakeTypes:
    """The type library, named types and per-function frames behind `ida_typeinf` / `ida_frame`."""

    def __init__(self):
        self.numbered = {}      # ordinal -> type dict
        self.named = {}         # name -> type dict
        self.frames = {}        # function start -> type dict
        self.landmarks = {}     # function start -> (savregs, retaddr, args) or None

    @staticmethod
    def type_(name, members=(), union=False, udt=True, size=None):
        return dict(name=name, members=list(members), union=union, udt=udt, size=size)

    def tinfo_class(self):
        types = self

        class FakeTif:
            def __init__(self):
                self.t = None

            def get_numbered_type(self, til, ordinal, *rest):
                self.t = types.numbered.get(ordinal)
                return self.t is not None

            def get_named_type(self, til, name, flags, resolve):
                self.t = types.named.get(name)
                return self.t is not None

            def get_function_frame(self, ea):
                self.t = types.frames.get(ea)
                return self.t is not None

            def is_udt(self):
                return self.t["udt"]

            def is_union(self):
                return self.t["union"]

            def get_type_name(self):
                return self.t["name"]

            def get_size(self):
                return self.t["size"] if self.t["size"] is not None else 0xFFFFFFFFFFFFFFFF

            def get_udt_nmembers(self):
                return len(self.t["members"])

            def get_udm(self, index):
                name, bits, size_bits, type_str, bitfield = self.t["members"][index]
                return index, SimpleNamespace(name=name, offset=bits, size=size_bits, type=type_str,
                                              is_bitfield=lambda: bitfield)

        return FakeTif

    def modules(self):
        types = self
        typeinf = SimpleNamespace(tinfo_class=None, BTF_TYPEDEF=1, get_idati=lambda: "til",
                                  get_ordinal_limit=lambda til: max(types.numbered, default=0) + 1)
        typeinf.tinfo_t = self.tinfo_class()
        frame = SimpleNamespace()
        frame.frame_off_savregs_ea = lambda ea: types.landmarks[ea][0]
        frame.frame_off_retaddr_ea = lambda ea: types.landmarks[ea][1]
        frame.frame_off_args_ea = lambda ea: types.landmarks[ea][2]
        frame.get_frame_size_ea = lambda ea: types.landmarks[ea][2]
        return {"ida_typeinf": typeinf, "ida_frame": frame}


class W2:
    pass


@pytest.fixture
def w2(monkeypatch):
    module, ida = _load_worker()
    db = FakeDatabase()
    model = CodeModel(db)
    model.segs = [(".text", 0x1000, 0x2000), (".rdata", 0x3000, 0x3100), (".idata", 0x4000, 0x4100),
                  (".rdata", 0x5000, 0x5100)]
    db.segments = {n: (s, e) for n, s, e in model.segs}
    db.wire(ida)
    model.wire(ida)
    types = FakeTypes()
    gdl = SimpleNamespace(fcb_normal=0, fcb_indjump=1, fcb_ret=2, fcb_cndret=3, fcb_noret=4, fcb_enoret=5,
                          fcb_extern=6, fcb_error=7, FlowChart=lambda func: [])
    search = SimpleNamespace(SEARCH_DOWN=1, SEARCH_NEXT=2)

    def find_imm(cursor, flags, value):
        hits = sorted(ea for ea, it in model.items.items() if ea > cursor and value in it["imms"].values())
        if not hits:
            return (BADADDR, 0)
        ea = hits[0]
        return (ea, next(i for i, v in model.items[ea]["imms"].items() if v == value))

    search.find_imm = find_imm
    for name, mod in {**types.modules(), "ida_gdl": gdl, "ida_search": search}.items():
        monkeypatch.setitem(sys.modules, name, mod)
    ctx = W2()
    ctx.module, ctx.ida, ctx.db, ctx.model, ctx.types, ctx.gdl = module, ida, db, model, types, gdl
    return ctx


def _w2_run(ctx, operation, query, max_results=200, offset=0):
    return _run(ctx.module, operation, query, max_results, offset)


# ---------------------------------------------------------------------------
# disasm_range
# ---------------------------------------------------------------------------
def _code_run(model):
    model.add_insn(0x1000, 4, "sub", ["rsp", "48h"], data=[0x48, 0x83, 0xEC, 0x48])
    model.add_insn(0x1004, 3, "mov", ["rax", "rcx"], data=[0x48, 0x89, 0xC8])
    model.add_data(0x1007, 8, data=[1, 2, 3, 4, 5, 6, 7, 8])
    # 0x100f.. are undefined bytes IDA decoded to nothing


def test_disasm_range_lists_instructions_with_operands_and_no_comment(w2):
    _code_run(w2.model)
    r = _w2_run(w2, "disasm_range", "0x1000 2")
    assert r["ok"] and r["stop_reason"] == "count_reached" and r["resume_address"] == "0x1007"
    assert [(i["address"], i["kind"], i["text"], i["bytes_hex"]) for i in r["items"]] == [
        ("0x1000", "instruction", "sub rsp, 48h", "4883ec48"), ("0x1004", "instruction", "mov rax, rcx", "4889c8")]
    assert r["items"][0]["operands"] == ["rsp", "48h"] and r["items"][0]["mnemonic"] == "sub"
    assert "comment" not in json.dumps(r["items"]) and r["instruction_count"] == 2


def test_defined_data_and_undefined_bytes_are_not_disassembled(w2):
    """Rule 4: a byte that is not an instruction never gets a mnemonic."""
    _code_run(w2.model)
    r = _w2_run(w2, "disasm_range", "0x1007 3")
    data_row, undefined_row = r["items"][0], r["items"][1]
    assert (data_row["kind"], data_row["mnemonic"], data_row["operands"], data_row["text"]) == ("data", None, None, None)
    assert data_row["size"] == 8 and data_row["bytes_hex"] == "0102030405060708"
    assert undefined_row["kind"] == "undefined" and undefined_row["mnemonic"] is None and undefined_row["text"] is None
    assert undefined_row["address"] == "0x100f" and undefined_row["size"] == 16
    assert r["undefined_row_count"] == 2 and r["instruction_count"] == 0


def test_undefined_bytes_with_no_value_have_null_bytes_not_zeros(w2):
    w2.model.add_insn(0x1000, 1, "nop", data=[0x90])
    r = _w2_run(w2, "disasm_range", "0x1001 1")
    assert r["items"][0]["kind"] == "undefined" and r["items"][0]["bytes_hex"] is None


def test_an_undefined_row_stops_at_the_next_defined_item(w2):
    w2.model.add_insn(0x1005, 1, "nop", data=[0x90])
    r = _w2_run(w2, "disasm_range", "0x1000 2")
    assert [(i["address"], i["kind"], i["size"]) for i in r["items"]] == [("0x1000", "undefined", 5), ("0x1005", "instruction", 1)]


def test_a_start_in_the_middle_of_an_instruction_is_said_so(w2):
    _code_run(w2.model)
    r = _w2_run(w2, "disasm_range", "0x1001 2")
    assert r["items"][0]["kind"] == "inside_item" and r["items"][0]["item_head"] == "0x1000"
    assert r["items"][0]["size"] == 3 and r["items"][0]["mnemonic"] is None
    assert r["items"][1]["address"] == "0x1004"


def test_an_end_address_bounds_the_walk_and_the_last_item_may_cross_it(w2):
    _code_run(w2.model)
    r = _w2_run(w2, "disasm_range", json.dumps({"address": "0x1000", "end": "0x1005"}))
    assert [i["address"] for i in r["items"]] == ["0x1000", "0x1004"]
    assert r["stop_reason"] == "end_address_reached" and r["resume_address"] is None


def test_the_walk_stops_where_the_segments_end(w2):
    w2.model.segs = [(".text", 0x1000, 0x1004)]
    w2.model.add_insn(0x1000, 4, "nop")
    r = _w2_run(w2, "disasm_range", "0x1000 10")
    assert len(r["items"]) == 1 and r["stop_reason"] == "left_mapped_segments"


def test_an_end_request_stops_at_the_2000_row_cap_and_says_where_to_resume(w2):
    w2.model.segs = [(".big", 0x10000, 0x20000)]
    for i in range(2100):
        w2.model.add_insn(0x10000 + i, 1, "nop")
    r = _w2_run(w2, "disasm_range", json.dumps({"address": 0x10000, "end": 0x20000}), max_results=5)
    assert r["total_row_count"] == 2000 and r["stop_reason"] == "row_cap_reached" and r["resume_address"] == hex(0x10000 + 2000)
    assert len(r["items"]) == 5 and r["truncated"] is True and r["next_offset"] == 5


def test_disasm_rows_page_with_offset(w2):
    _code_run(w2.model)
    first = _w2_run(w2, "disasm_range", "0x1000 3", max_results=2)
    assert first["next_offset"] == 2 and first["truncated"] is True and first["total_row_count"] == 3
    rest = _w2_run(w2, "disasm_range", "0x1000 3", max_results=2, offset=2)
    assert [i["kind"] for i in rest["items"]] == ["data"] and rest["next_offset"] is None


def test_an_unmapped_start_is_an_error(w2):
    r = _w2_run(w2, "disasm_range", "0x10 4")
    assert (r["ok"], r["error"]) == (False, "ADDRESS_NOT_MAPPED")


DISASM_QUERIES = [
    "0x1000 4", "0x1000,4", "0x1000 2000", "0x1000 2001", "0x1000 0", "0x1000 -1", "0x1000", "", "zz 4",
    "-5 4", "0xffffffffffffffff 4", '{"address": "0x1000", "count": 8}', '{"address": "0x1000", "end": "0x1100"}',
    '{"address": "0x1000", "end": "0x1000"}', '{"address": "0x1000", "end": "0x0fff"}',
    '{"address": "0x1000", "count": 8, "end": "0x1100"}', '{"address": "0x1000"}', '{"count": 4}',
    '{"address": "0x1000", "count": true}', '{"address": "0x1000", "count": 4.0}', '{"address": "0x1000", "bogus": 1}',
    "[]", "{", '{"address": "0x1000", "end": "0x10000000000000000"}',
]
FUNCTION_QUERIES = ["", "   ", "start", "0x1000", "x" * 512, "x" * 513]
CALLGRAPH_QUERIES = [
    "", "start", "0x1000", '{"function": "start"}', '{"function": "start", "depth": 4, "max_nodes": 500}',
    '{"function": "start", "depth": 0}', '{"function": "start", "depth": 5}', '{"function": "start", "max_nodes": 0}',
    '{"function": "start", "max_nodes": 501}', '{"function": "start", "depth": true}', '{"function": "start", "depth": "3"}',
    '{"function": 5}', '{"depth": 2}', '{"function": "", "depth": 2}', '{"function": "start", "extra": 1}', "{", "[]",
]
FIND_BYTES_QUERIES = [
    "48 8B ?? 05", "48 8b ? 05", "48", "??", "? ?", "", "   ", "4", "488B", "48 8B 05 zz", "48,8B", " ".join(["90"] * 256),
    " ".join(["90"] * 257), '{"pattern": "48 8B"}', '{"pattern": "48 8B", "segment": ".text"}',
    '{"pattern": "48 8B", "start": "0x1000", "end": "0x2000"}', '{"pattern": "48 8B", "start": "0x2000", "end": "0x1000"}',
    '{"pattern": "48 8B", "start": "0x1000", "segment": ".text"}', '{"pattern": "48 8B", "segment": ""}',
    '{"pattern": "48 8B", "segment": 5}', '{"pattern": "48 8B", "start": "zz"}', '{"pattern": "48 8B", "end": 0}',
    '{"pattern": "48 8B", "end": "0x10000000000000000"}', '{"pattern": 5}', '{"start": "0x1000"}', '{"pattern": "48", "x": 1}',
    '{"pattern": "?? ??"}', "{",
]
FIND_IMMEDIATE_QUERIES = [
    "0x5A827999", "1518500249", "0", "0xffffffffffffffff", "0x10000000000000000", "-1", "", "abc", "1.5",
    '{"value": "0x5A827999"}', '{"value": 5}', '{"value": true}', '{"value": -5}', '{"value": "0x5", "segment": ".text"}',
    '{"value": "0x5", "start": "0x1000", "end": "0x2000"}', '{"value": "0x5", "start": "0x2000", "end": "0x1000"}',
    '{"value": "0x5", "start": "0x1000", "segment": ".text"}', '{"start": "0x1000"}', '{"value": 5, "bogus": 1}', "{",
]
NAME_QUERIES = ["", "  ", "_GUID", "GUID", "x" * 256, "x" * 257, "a\nb", "a\tb", "café", "\x00"]


@pytest.mark.contract
@pytest.mark.parametrize("operation, queries", [
    ("disasm_range", DISASM_QUERIES), ("basic_blocks", FUNCTION_QUERIES), ("stack_frame", FUNCTION_QUERIES),
    ("local_variables", FUNCTION_QUERIES), ("callgraph", CALLGRAPH_QUERIES), ("find_bytes", FIND_BYTES_QUERIES),
    ("find_immediate", FIND_IMMEDIATE_QUERIES), ("get_struct", NAME_QUERIES), ("list_structs", NAME_QUERIES),
    ("flirt_signatures", ["", "  ", "x", "0x1"]),
])
def test_wrapper_and_worker_agree_on_which_listing_requests_are_bad(w2, operation, queries):
    """The wrapper refuses before IDA starts and the worker re-checks: the two grammars must not drift. Only the
    request error is compared; what the engine alone can answer (an address outside every segment, an unknown
    function or segment or type) is not part of the request grammar."""
    request_errors = {
        "disasm_range": {"INVALID_DISASM_RANGE_REQUEST", "INVALID_ADDRESS", "INVALID_COUNT", "INVALID_END_ADDRESS"},
        "basic_blocks": {"FUNCTION_REQUIRED"}, "stack_frame": {"FUNCTION_REQUIRED"},
        "local_variables": {"FUNCTION_REQUIRED"},
        "callgraph": {"INVALID_CALLGRAPH_REQUEST", "FUNCTION_REQUIRED", "INVALID_DEPTH", "INVALID_MAX_NODES"},
        "find_bytes": {"INVALID_FIND_BYTES_REQUEST", "INVALID_PATTERN", "INVALID_ADDRESS", "INVALID_RANGE"},
        "find_immediate": {"INVALID_FIND_IMMEDIATE_REQUEST", "INVALID_VALUE", "INVALID_ADDRESS", "INVALID_RANGE"},
        "get_struct": {"INVALID_TYPE_NAME"}, "list_structs": {"INVALID_FILTER"}, "flirt_signatures": {"UNEXPECTED_QUERY"},
    }[operation]
    for query in queries:
        worker_error = _w2_run(w2, operation, query).get("error")
        if worker_error not in request_errors:
            worker_error = None
        assert ti._query_request_problem(operation, query) == worker_error, (operation, query)


def test_every_listing_request_error_is_raised_by_the_worker_for_a_bad_request(w2):
    """The battery above must actually contain bad requests, not only good ones."""
    for operation, queries in (("disasm_range", DISASM_QUERIES), ("callgraph", CALLGRAPH_QUERIES),
                               ("find_bytes", FIND_BYTES_QUERIES), ("find_immediate", FIND_IMMEDIATE_QUERIES)):
        assert sum(1 for q in queries if ti._query_request_problem(operation, q)) >= len(queries) // 2, operation


# ---------------------------------------------------------------------------
# basic_blocks
# ---------------------------------------------------------------------------
def _block(start, end, type_, succs=(), preds=()):
    return SimpleNamespace(start_ea=start, end_ea=end, type=type_, succs=lambda: list(succs), preds=lambda: list(preds))


def _flow(w2, blocks):
    w2.db.names["f"] = 0x1000
    w2.db.functions[0x1000] = (0x1100, 0)
    w2.gdl.FlowChart = lambda func: blocks


def test_basic_blocks_lists_start_end_type_and_neighbours(w2):
    a, b, c = _block(0x1000, 0x1010, 0), _block(0x1010, 0x1020, 0), _block(0x1020, 0x1030, 2)
    a.succs = lambda: [c, b]
    b.preds, b.succs = (lambda: [a]), (lambda: [c])
    c.preds = lambda: [b, a]
    _flow(w2, [c, a, b])
    r = _w2_run(w2, "basic_blocks", "f")
    assert [(i["start"], i["end"], i["type"]) for i in r["items"]] == [
        ("0x1000", "0x1010", "normal"), ("0x1010", "0x1020", "normal"), ("0x1020", "0x1030", "return")]
    assert r["items"][0]["successors"] == ["0x1010", "0x1020"] and r["items"][2]["predecessors"] == ["0x1000", "0x1010"]
    assert r["total_block_count"] == 3 and r["edge_count"] == 3 and r["function"]["address"] == "0x1000"


@pytest.mark.parametrize("code, name", [(0, "normal"), (1, "indirect_jump"), (2, "return"), (3, "conditional_return"),
                                        (4, "no_return"), (5, "external_no_return"), (6, "external"), (7, "error"),
                                        (99, "UNKNOWN")])
def test_each_block_type_has_its_name_and_an_unknown_code_stays_unknown(w2, code, name):
    _flow(w2, [_block(0x1000, 0x1010, code)])
    r = _w2_run(w2, "basic_blocks", "f")
    assert r["items"][0]["type"] == name and r["items"][0]["type_code"] == code


def test_an_indirect_jump_block_lists_only_the_successors_ida_recorded(w2):
    _flow(w2, [_block(0x1000, 0x1010, 1)])
    assert _w2_run(w2, "basic_blocks", "f")["items"][0]["successors"] == []


def test_block_neighbour_lists_are_cut_with_the_true_count(w2):
    many = [_block(0x1100 + i, 0x1101 + i, 0) for i in range(300)]
    _flow(w2, [_block(0x1000, 0x1010, 1, succs=many)])
    row = _w2_run(w2, "basic_blocks", "f")["items"][0]
    assert row["successor_count"] == 300 and len(row["successors"]) == 256 and row["edge_lists_truncated"] is True


def test_basic_blocks_page_and_errors(w2):
    _flow(w2, [_block(0x1000 + 0x10 * i, 0x1010 + 0x10 * i, 0) for i in range(5)])
    r = _w2_run(w2, "basic_blocks", "0x1004", max_results=2, offset=1)
    assert [i["start"] for i in r["items"]] == ["0x1010", "0x1020"] and r["next_offset"] == 3 and r["truncated"] is True
    assert _w2_run(w2, "basic_blocks", "nope")["error"] == "FUNCTION_NOT_FOUND"
    assert _w2_run(w2, "basic_blocks", "")["error"] == "FUNCTION_REQUIRED"


# ---------------------------------------------------------------------------
# callgraph
# ---------------------------------------------------------------------------
def _graph(w2):
    """root -> {a (direct, twice), CreateFileW (import), a register call}; a -> {b}; b -> {c}; thunk -> slot."""
    m, db = w2.model, w2.db
    db.functions.update({0x1000: (0x1100, 0), 0x1100: (0x1200, 0), 0x1200: (0x1300, 0), 0x1300: (0x1400, 0),
                         0x1500: (0x1510, FUNC_THUNK)})
    db.names.update({"root": 0x1000, "a": 0x1100, "b": 0x1200, "c": 0x1300, "thunk": 0x1500})
    db.imports = [("KERNEL32", "CreateFileW", None, 0x4010), ("KERNEL32", "Sleep", None, 0x4018)]
    m.add_insn(0x1000, 5, "call", ["a"], [OT_NEAR], call=True)
    m.add_insn(0x1010, 5, "call", ["a"], [OT_NEAR], call=True)
    m.add_insn(0x1020, 6, "call", ["cs:CreateFileW"], [OT_MEM], call=True)
    m.add_insn(0x1030, 2, "call", ["rax"], [OT_REG], call=True)
    m.add_insn(0x1040, 6, "call", ["cs:fptr"], [OT_MEM], call=True)
    m.add_insn(0x1050, 3, "mov", ["rax", "rbx"])
    m.add_insn(0x1100, 5, "call", ["b"], [OT_NEAR], call=True)
    m.add_insn(0x1200, 5, "call", ["c"], [OT_NEAR], call=True)
    m.add_insn(0x1500, 6, "jmp", ["cs:Sleep"], [OT_MEM])
    db.refs_from = {
        0x1000: [_xref(0x1000, 0x1100, FL_CN, True)], 0x1010: [_xref(0x1010, 0x1100, FL_CN, True)],
        0x1020: [_xref(0x1020, 0x4010, FL_CN, True), _xref(0x1020, 0x4010, 3, False)],
        0x1040: [_xref(0x1040, 0x6000, FL_CN, True)],       # a memory call IDA resolved to a non-import address
        0x1100: [_xref(0x1100, 0x1200, FL_CN, True)], 0x1200: [_xref(0x1200, 0x1300, FL_CN, True)],
        0x1500: [_xref(0x1500, 0x4018, 3, False)],
    }


def _edges(r):
    return sorted((e["from"], e["to"], e["kind"], e["call_count"]) for e in r["items"])


def test_callgraph_has_direct_edges_import_edges_and_merges_repeated_calls(w2):
    _graph(w2)
    r = _w2_run(w2, "callgraph", json.dumps({"function": "root", "depth": 3}))
    assert r["ok"] and r["root"] == "0x1000"
    assert _edges(r) == [("0x1000", "0x1100", "direct", 2), ("0x1000", "0x4010", "import", 1),
                         ("0x1100", "0x1200", "direct", 1), ("0x1200", "0x1300", "direct", 1)]
    direct = next(e for e in r["items"] if e["to"] == "0x1100")
    assert direct["call_sites"] == ["0x1000", "0x1010"]
    nodes = {n["address"]: n for n in r["nodes"]}
    assert nodes["0x4010"]["is_import"] is True and nodes["0x4010"]["name"] == "CreateFileW"
    assert nodes["0x4010"]["import_module"] == "KERNEL32" and nodes["0x4010"]["not_expanded_reason"] == "import"
    assert nodes["0x1100"]["is_import"] is False and nodes["0x1100"]["is_function"] is True


def test_indirect_calls_are_counted_and_never_resolved(w2):
    """Rule 4: a call through a register, or through a memory operand that is not an import slot, is no edge."""
    _graph(w2)
    r = _w2_run(w2, "callgraph", "root")
    root = r["nodes"][0]
    assert root["indirect_call_count"] == 2 and root["indirect_call_sites"] == ["0x1030", "0x1040"]
    assert r["indirect_call_total"] == 2
    assert all(e["to"] != "0x6000" for e in r["items"]) and "0x6000" not in {n["address"] for n in r["nodes"]}
    assert "never resolved" in r["indirect_calls_note"]


def test_the_depth_limit_marks_functions_that_were_not_looked_into(w2):
    _graph(w2)
    r = _w2_run(w2, "callgraph", json.dumps({"function": "root", "depth": 1}))
    nodes = {n["address"]: n for n in r["nodes"]}
    assert nodes["0x1000"]["expanded"] is True and nodes["0x1100"]["expanded"] is False
    assert nodes["0x1100"]["not_expanded_reason"] == "depth_limit" and nodes["0x1100"]["depth"] == 1
    assert "0x1200" not in nodes
    deeper = _w2_run(w2, "callgraph", json.dumps({"function": "root", "depth": 2}))
    assert "0x1200" in {n["address"] for n in deeper["nodes"]}


def test_the_node_cap_is_reported_and_edges_to_dropped_nodes_are_counted(w2):
    _graph(w2)
    r = _w2_run(w2, "callgraph", json.dumps({"function": "root", "depth": 3, "max_nodes": 2}))
    assert r["node_count"] == 2 and r["nodes_truncated"] is True and r["dropped_node_count"] >= 1
    assert r["edges_not_recorded"] >= 1
    assert len(r["nodes"]) == 2


def test_a_thunk_function_has_an_edge_to_the_import_it_jumps_through(w2):
    _graph(w2)
    r = _w2_run(w2, "callgraph", "thunk")
    assert _edges(r) == [("0x1500", "0x4018", "import", 1)] and r["nodes"][0]["is_thunk"] is True


def test_a_call_to_a_non_function_address_is_a_leaf_not_expanded(w2):
    _graph(w2)
    w2.db.refs_from[0x1000] = [_xref(0x1000, 0x1700, FL_CN, True)]
    r = _w2_run(w2, "callgraph", "root")
    node = next(n for n in r["nodes"] if n["address"] == "0x1700")
    assert node["is_function"] is False and node["not_expanded_reason"] == "not_a_function"


def test_callgraph_pages_the_edges_and_reports_unknown_functions(w2):
    _graph(w2)
    r = _w2_run(w2, "callgraph", json.dumps({"function": "root", "depth": 3}), max_results=1)
    assert len(r["items"]) == 1 and r["next_offset"] == 1 and r["total_edge_count"] == 4 and len(r["nodes"]) == 5
    assert _w2_run(w2, "callgraph", "nope")["error"] == "FUNCTION_NOT_FOUND"
    assert _w2_run(w2, "callgraph", '{"function": "root", "depth": 9}')["error"] == "INVALID_DEPTH"


# ---------------------------------------------------------------------------
# stack_frame
# ---------------------------------------------------------------------------
def _frame(w2, landmarks=(136, 136, 144)):
    w2.db.names["g"] = 0x1000
    w2.db.functions[0x1000] = (0x1100, 0)
    w2.db.functions[0x1100] = (0x1200, 0)
    w2.db.names["h"] = 0x1100
    w2.types.frames[0x1000] = FakeTypes.type_("frame", [
        ("var_68", 32 * 8, 4 * 8, "ULONG", False), ("var_18", 112 * 8, 8 * 8, "_QWORD", False),
        ("__saved", 128 * 8, 8 * 8, "_QWORD", False), ("__return_address", 136 * 8, 8 * 8, "_UNKNOWN *", False),
        ("arg_20", 176 * 8, 8 * 8, "_QWORD", False)])
    w2.types.landmarks[0x1000] = landmarks


def test_stack_frame_separates_locals_saved_registers_return_address_and_arguments(w2):
    _frame(w2)
    r = _w2_run(w2, "stack_frame", "g")
    assert r["ok"]
    assert [(i["name"], i["region"], i["is_argument"]) for i in r["items"]] == [
        ("var_68", "local", False), ("var_18", "local", False), ("__saved", "local", False),
        ("__return_address", "return_address", False), ("arg_20", "argument", True)]
    first = r["items"][0]
    assert (first["offset"], first["size"], first["type_str"], first["offset_from_return_address"]) == (32, 4, "ULONG", -104)
    assert r["landmarks"] == {"saved_registers_offset": 136, "return_address_offset": 136, "arguments_offset": 144}
    assert r["frame_size"] == 144 and r["total_member_count"] == 5


def test_a_saved_register_member_is_told_apart_when_ida_recorded_a_saved_area(w2):
    _frame(w2, (128, 136, 144))
    regions = {i["name"]: i["region"] for i in _w2_run(w2, "stack_frame", "g")["items"]}
    assert regions["__saved"] == "saved_registers" and regions["var_18"] == "local"


def test_a_function_with_no_frame_is_an_error_and_nothing_is_inferred(w2):
    _frame(w2)
    r = _w2_run(w2, "stack_frame", "h")
    assert (r["ok"], r["error"]) == (False, "NO_STACK_FRAME") and "items" in r and r["items"] == []
    assert r["function"]["address"] == "0x1100"


def test_unavailable_landmarks_leave_the_region_null(w2):
    _frame(w2)
    w2.types.landmarks.clear()           # frame_off_* raises KeyError: IDA gives no landmark
    r = _w2_run(w2, "stack_frame", "g")
    assert r["ok"] and all(i["region"] is None and i["is_argument"] is None for i in r["items"])
    assert r["landmarks"] == {"saved_registers_offset": None, "return_address_offset": None, "arguments_offset": None}


def test_stack_frame_pages_and_rejects_unknown_functions(w2):
    _frame(w2)
    r = _w2_run(w2, "stack_frame", "g", max_results=2, offset=3)
    assert [i["name"] for i in r["items"]] == ["__return_address", "arg_20"] and r["next_offset"] is None
    assert _w2_run(w2, "stack_frame", "nope")["error"] == "FUNCTION_NOT_FOUND"


# ---------------------------------------------------------------------------
# local_variables
# ---------------------------------------------------------------------------
def _location(kind, **kw):
    flags = {"is_stkoff": False, "is_reg1": False, "is_reg2": False, "is_scattered": False, "is_rrel": False,
             "is_ea": False}
    flags["is_" + kind] = True if kind != "stack" else False
    if kind == "stack":
        flags["is_stkoff"] = True
    loc = SimpleNamespace(**{k: (lambda v=v: v) for k, v in flags.items()})
    loc.stkoff = lambda: kw.get("stkoff")
    loc.reg1, loc.reg2, loc.regoff = (lambda: kw.get("reg1")), (lambda: kw.get("reg2")), (lambda: kw.get("regoff", 0))
    loc.get_ea = lambda: kw.get("ea")
    return loc


def _lvar(name, type_, is_arg, location, width=8):
    return SimpleNamespace(name=name, type=lambda: type_, is_arg_var=is_arg, width=width, location=location)


def _hexrays(w2, lvars):
    w2.db.names["f"] = 0x1000
    w2.db.functions[0x1000] = (0x1100, 0)
    hx = w2.ida["ida_hexrays"]
    hx.init_hexrays_plugin.return_value = True
    hx.get_mreg_name.side_effect = lambda reg, width: {24: "rcx", 16: "rax"}.get(reg, "r%d" % reg)
    hx.decompile.side_effect = lambda ea: SimpleNamespace(lvars=lvars)


def test_local_variables_report_name_type_arg_and_location(w2):
    _hexrays(w2, [_lvar("a1", "__int64", True, _location("reg1", reg1=24)),
                  _lvar("v7", "struct S", False, _location("stack", stkoff=48), 16),
                  _lvar("", "int", False, _location("reg2", reg1=24, reg2=16), 8),
                  _lvar("g", "int", False, _location("ea", ea=0x3000)),
                  _lvar("s", "int", False, _location("scattered")), _lvar("r", "int", False, _location("rrel")),
                  _lvar("u", "int", False, _location("nothing"))])
    r = _w2_run(w2, "local_variables", "f")
    assert r["ok"] and r["decompiler"] == "hexrays" and r["total_variable_count"] == 7
    by = {i["index"]: i for i in r["items"]}
    assert (by[0]["name"], by[0]["type"], by[0]["is_arg"], by[0]["size"]) == ("a1", "__int64", True, 8)
    assert by[0]["location"] == {"kind": "register", "register": "rcx", "register_number": 24, "register_offset": 0}
    assert by[1]["is_arg"] is False and by[1]["location"]["kind"] == "stack" and by[1]["location"]["stack_offset"] == 48
    assert by[2]["name"] is None and by[2]["location"] == {"kind": "register_pair", "registers": ["rcx", "rax"]}
    assert by[3]["location"] == {"kind": "static", "address": "0x3000"}
    assert [by[i]["location"]["kind"] for i in (4, 5, 6)] == ["scattered", "register_relative", "unknown"]


def test_no_decompiler_is_an_error_not_a_list_from_the_frame(w2):
    _hexrays(w2, [])
    w2.ida["ida_hexrays"].init_hexrays_plugin.return_value = False
    r = _w2_run(w2, "local_variables", "f")
    assert (r["ok"], r["error"]) == (False, "HEXRAYS_NOT_AVAILABLE") and r["items"] == []


def test_a_failed_decompile_is_an_error_with_the_reason(w2):
    _hexrays(w2, [])
    w2.ida["ida_hexrays"].decompile.side_effect = w2.ida["ida_hexrays"].DecompilationFailure("call analysis failed")
    r = _w2_run(w2, "local_variables", "f")
    assert (r["ok"], r["error"]) == (False, "HEXRAYS_DECOMPILE_FAILED") and "call analysis failed" in r["detail"]
    w2.ida["ida_hexrays"].decompile.side_effect = lambda ea: None
    assert _w2_run(w2, "local_variables", "f")["error"] == "HEXRAYS_DECOMPILE_FAILED"


def test_local_variables_page_and_unknown_function(w2):
    _hexrays(w2, [_lvar("v%d" % i, "int", False, _location("stack", stkoff=i)) for i in range(5)])
    r = _w2_run(w2, "local_variables", "f", max_results=2, offset=4)
    assert [i["name"] for i in r["items"]] == ["v4"] and r["next_offset"] is None
    assert _w2_run(w2, "local_variables", "nope")["error"] == "FUNCTION_NOT_FOUND"


# ---------------------------------------------------------------------------
# find_bytes
# ---------------------------------------------------------------------------
def _bytes_db(w2):
    m = w2.model
    m.add_insn(0x1000, 4, "mov", ["rax", "[rbx+5]"], data=[0x48, 0x8B, 0x43, 0x05])
    m.add_insn(0x1010, 4, "mov", ["rcx", "[rbx+5]"], data=[0x48, 0x8B, 0x4B, 0x05])
    m.add_insn(0x1020, 4, "mov", ["rdx", "[rbx+6]"], data=[0x48, 0x8B, 0x53, 0x06])
    w2.db.loaded.update({0x3000: 0x48, 0x3001: 0x8B, 0x3002: 0x00, 0x3003: 0x05})
    w2.db.loaded.update({0x5000: 0x48, 0x5001: 0x8B, 0x5002: 0x00, 0x5003: 0x05})
    w2.db.functions[0x1000] = (0x1018, 0)
    w2.db.names["fn"] = 0x1000


def test_find_bytes_matches_wildcards_in_address_order_with_the_function(w2):
    _bytes_db(w2)
    r = _w2_run(w2, "find_bytes", "48 8b ?? 05")
    assert [(i["address"], i["bytes_hex"], i["segment"]) for i in r["items"]] == [
        ("0x1000", "488b4305", ".text"), ("0x1010", "488b4b05", ".text"), ("0x3000", "488b0005", ".rdata"),
        ("0x5000", "488b0005", ".rdata")]
    assert r["items"][0]["function"] == {"address": "0x1000", "name": "fn"}
    assert r["items"][2]["function"] is None            # no function there: null, not a guess
    assert r["pattern"] == "48 8B ? 05" and r["truncated"] is False and r["next_offset"] is None


def test_find_bytes_caps_the_matches_and_resumes(w2):
    _bytes_db(w2)
    first = _w2_run(w2, "find_bytes", "48 8B", max_results=2)
    assert len(first["items"]) == 2 and first["truncated"] is True and first["next_offset"] == 2
    rest = _w2_run(w2, "find_bytes", "48 8B", max_results=10, offset=2)
    assert [i["address"] for i in rest["items"]] == ["0x1020", "0x3000", "0x5000"] and rest["next_offset"] is None


def test_find_bytes_in_a_range_and_in_a_segment_name_that_repeats(w2):
    _bytes_db(w2)
    ranged = _w2_run(w2, "find_bytes", json.dumps({"pattern": "48 8B", "start": "0x1005", "end": "0x1021"}))
    assert [i["address"] for i in ranged["items"]] == ["0x1010"]       # 0x1020 does not fit inside the range
    named = _w2_run(w2, "find_bytes", json.dumps({"pattern": "48 8B", "segment": ".rdata"}))
    assert [i["address"] for i in named["items"]] == ["0x3000", "0x5000"]
    assert named["ranges"] == [{"start": "0x3000", "end": "0x3100"}, {"start": "0x5000", "end": "0x5100"}]


def test_find_bytes_unknown_segment_lists_the_known_names(w2):
    _bytes_db(w2)
    r = _w2_run(w2, "find_bytes", json.dumps({"pattern": "48", "segment": ".nope"}))
    assert (r["ok"], r["error"]) == (False, "SEGMENT_NOT_FOUND") and ".text" in r["segment_names"]


def test_find_bytes_with_no_match_is_an_ok_empty_list_that_states_its_scope(w2):
    _bytes_db(w2)
    r = _w2_run(w2, "find_bytes", "DE AD BE EF")
    assert r["ok"] and r["items"] == [] and "never match" in r["search_scope"]


def test_find_bytes_refuses_a_bad_pattern(w2):
    assert _w2_run(w2, "find_bytes", "?? ??")["error"] == "INVALID_PATTERN"
    assert _w2_run(w2, "find_bytes", "48 8")["error"] == "INVALID_PATTERN"


# ---------------------------------------------------------------------------
# find_immediate
# ---------------------------------------------------------------------------
def _imm_db(w2):
    m = w2.model
    m.add_insn(0x1000, 5, "mov", ["eax", "5A827999h"], [OT_REG, OT_IMM], imms={1: 0x5A827999})
    m.add_insn(0x1010, 6, "add", ["ebx", "5A827999h"], [OT_REG, OT_IMM], imms={1: 0x5A827999})
    m.add_insn(0x1020, 5, "mov", ["eax", "6ED9EBA1h"], [OT_REG, OT_IMM], imms={1: 0x6ED9EBA1})
    m.add_insn(0x1030, 5, "cmp", ["eax", "5A827999h"], [OT_REG, OT_IMM], imms={1: 0x5A827999})
    w2.db.functions[0x1000] = (0x1018, 0)
    w2.db.names["fn"] = 0x1000


def test_find_immediate_gives_address_operand_function_and_instruction_text(w2):
    _imm_db(w2)
    r = _w2_run(w2, "find_immediate", "0x5A827999")
    assert [(i["address"], i["operand_index"], i["instruction"]) for i in r["items"]] == [
        ("0x1000", 1, "mov eax, 5A827999h"), ("0x1010", 1, "add ebx, 5A827999h"), ("0x1030", 1, "cmp eax, 5A827999h")]
    assert r["items"][0]["function"] == {"address": "0x1000", "name": "fn"} and r["items"][2]["function"] is None
    assert r["value"] == "0x5a827999" and "different number" in r["search_scope"]


def test_find_immediate_includes_a_match_at_the_start_of_the_range(w2):
    _imm_db(w2)
    r = _w2_run(w2, "find_immediate", json.dumps({"value": "0x5A827999", "start": "0x1010", "end": "0x1031"}))
    assert [i["address"] for i in r["items"]] == ["0x1010", "0x1030"]
    limited = _w2_run(w2, "find_immediate", json.dumps({"value": "0x5A827999", "start": "0x1000", "end": "0x1010"}))
    assert [i["address"] for i in limited["items"]] == ["0x1000"]


def test_find_immediate_pages_and_accepts_decimal(w2):
    _imm_db(w2)
    first = _w2_run(w2, "find_immediate", str(0x5A827999), max_results=1)
    assert [i["address"] for i in first["items"]] == ["0x1000"] and first["truncated"] and first["next_offset"] == 1
    rest = _w2_run(w2, "find_immediate", "0x5A827999", max_results=5, offset=1)
    assert [i["address"] for i in rest["items"]] == ["0x1010", "0x1030"] and rest["next_offset"] is None


def test_find_immediate_with_no_match_is_an_ok_empty_list_and_a_negative_is_refused(w2):
    _imm_db(w2)
    r = _w2_run(w2, "find_immediate", "0x1234")
    assert r["ok"] and r["items"] == []
    assert _w2_run(w2, "find_immediate", "-1")["error"] == "INVALID_VALUE"
    assert _w2_run(w2, "find_immediate", json.dumps({"value": 5, "segment": ".nope"}))["error"] == "SEGMENT_NOT_FOUND"


# ---------------------------------------------------------------------------
# list_structs / get_struct
# ---------------------------------------------------------------------------
def _types(w2):
    t = w2.types
    guid = FakeTypes.type_("_GUID", [("Data1", 0, 32, "unsigned int", False), ("Data4", 64, 64, "unsigned __int8[8]", False)],
                           size=16)
    union = FakeTypes.type_("U", [("a", 0, 32, "int", False), ("b", 0, 8, "char", False)], union=True, size=4)
    flags = FakeTypes.type_("Flags", [("lo", 0, 3, "unsigned int", True), ("hi", 3, 5, "unsigned int", True)], size=1)
    enum = FakeTypes.type_("Color", udt=False)
    forward = FakeTypes.type_("Fwd", [], size=None)
    t.numbered = {1: guid, 2: enum, 3: union, 4: flags, 5: forward}
    t.named = {"_GUID": guid, "U": union, "Flags": flags, "Color": enum, "GUID": guid}


def test_list_structs_gives_name_kind_size_and_member_count_for_udts_only(w2):
    _types(w2)
    r = _w2_run(w2, "list_structs", "")
    assert [(i["name"], i["ordinal"], i["kind"], i["size"], i["member_count"]) for i in r["items"]] == [
        ("_GUID", 1, "struct", 16, 2), ("U", 3, "union", 4, 2), ("Flags", 4, "struct", 1, 2), ("Fwd", 5, "struct", None, 0)]
    assert r["total_struct_count"] == 4 and r["next_offset"] is None


def test_list_structs_filters_case_insensitively_and_pages(w2):
    _types(w2)
    assert [i["name"] for i in _w2_run(w2, "list_structs", "guid")["items"]] == ["_GUID"]
    first = _w2_run(w2, "list_structs", "", max_results=2)
    assert first["truncated"] is True and first["next_offset"] == 2 and first["total_struct_count"] == 4
    rest = _w2_run(w2, "list_structs", "", max_results=5, offset=2)
    assert [i["name"] for i in rest["items"]] == ["Flags", "Fwd"] and rest["next_offset"] is None


def test_get_struct_lists_members_with_offset_size_and_type(w2):
    _types(w2)
    r = _w2_run(w2, "get_struct", "_GUID")
    assert r["ok"] and r["kind"] == "struct" and r["size"] == 16 and r["member_count"] == 2
    assert [(i["name"], i["offset"], i["size"], i["type_str"]) for i in r["items"]] == [
        ("Data1", 0, 4, "unsigned int"), ("Data4", 8, 8, "unsigned __int8[8]")]


def test_get_struct_tries_the_underscore_counterpart(w2):
    _types(w2)
    r = _w2_run(w2, "get_struct", "GUID")
    assert r["resolved_type_name"] == "GUID" and r["tried_type_names"] == ["GUID", "_GUID"]
    w2.types.named.pop("GUID")
    r = _w2_run(w2, "get_struct", "GUID")
    assert r["ok"] and r["resolved_type_name"] == "_GUID"


def test_get_struct_keeps_bit_exact_offsets_for_bitfields_and_union_members_share_offset_zero(w2):
    _types(w2)
    flags = _w2_run(w2, "get_struct", "Flags")["items"]
    assert [(i["offset"], i["offset_bits"], i["size"], i["size_bits"], i["byte_aligned"], i["is_bitfield"])
            for i in flags] == [(0, 0, None, 3, True, True), (0, 3, None, 5, False, True)]
    union = _w2_run(w2, "get_struct", "U")
    assert union["kind"] == "union" and [i["offset"] for i in union["items"]] == [0, 0]


def test_get_struct_errors_keep_no_type_apart_from_not_a_struct(w2):
    _types(w2)
    assert _w2_run(w2, "get_struct", "Nope")["error"] == "TYPE_NOT_FOUND"
    r = _w2_run(w2, "get_struct", "Color")
    assert r["error"] == "TYPE_NOT_STRUCT_OR_UNION" and r["tried_type_names"] == ["Color", "_Color"]


def test_get_struct_pages_members(w2):
    _types(w2)
    r = _w2_run(w2, "get_struct", "_GUID", max_results=1, offset=1)
    assert [i["name"] for i in r["items"]] == ["Data4"] and r["total_member_count"] == 2 and r["next_offset"] is None


# ---------------------------------------------------------------------------
# flirt_signatures
# ---------------------------------------------------------------------------
def _flirt(w2, descs, states=None, title="Title"):
    funcs = w2.ida["ida_funcs"]
    funcs.IDASGN_APPLIED, funcs.IDASGN_PLANNED, funcs.IDASGN_CURRENT = 2, 1, 3
    funcs.get_idasgn_qty.return_value = len(descs)
    funcs.get_idasgn_desc_with_matches.side_effect = lambda i: descs[i]
    funcs.calc_idasgn_state.side_effect = lambda i: (states or {}).get(i, 2)
    funcs.get_idasgn_title.side_effect = lambda name: "%s of %s" % (title, name)


def test_flirt_signatures_list_state_and_matched_counts_and_keep_the_library_flag_count_apart(w2):
    _flirt(w2, [("vc64_14", "vc64mfc", 50), ("vc64ucrt", "", 1), ("seh", "x", 0)], {1: 1, 2: 99})
    w2.db.functions.update({0x1000: (0x1010, FUNC_LIB), 0x1010: (0x1020, 0), 0x1020: (0x1030, FUNC_LIB)})
    r = _w2_run(w2, "flirt_signatures", "")
    assert [(i["name"], i["matched_function_count"], i["state"], i["optional_libraries"]) for i in r["items"]] == [
        ("vc64_14", 50, "applied", "vc64mfc"), ("vc64ucrt", 1, "planned", None), ("seh", 0, "UNKNOWN", "x")]
    assert r["items"][0]["title"] == "Title of vc64_14" and r["signature_count"] == 3
    assert r["library_flagged_function_count"] == 2 and "not summed" in r["note"]


def test_a_signature_ida_cannot_describe_has_null_fields_not_zeros(w2):
    _flirt(w2, [None, ("known", "", 3)])
    r = _w2_run(w2, "flirt_signatures", "")
    assert r["items"][0] == {"index": 0, "name": None, "title": None, "optional_libraries": None,
                             "matched_function_count": None, "state": "applied"}
    assert r["items"][1]["matched_function_count"] == 3


def test_flirt_signatures_with_none_loaded_is_an_ok_empty_list_and_takes_no_query(w2):
    _flirt(w2, [])
    r = _w2_run(w2, "flirt_signatures", "")
    assert r["ok"] and r["items"] == [] and r["signature_count"] == 0
    assert _w2_run(w2, "flirt_signatures", "vc")["error"] == "UNEXPECTED_QUERY"


# ---------------------------------------------------------------------------
# the operations are read-only, dispatched and listed
# ---------------------------------------------------------------------------
W2_OPERATIONS = ("disasm_range", "basic_blocks", "callgraph", "stack_frame", "local_variables", "find_bytes",
                 "find_immediate", "list_structs", "get_struct", "flirt_signatures")
MUTATING_PREFIXES = ("set_", "put_", "del_", "delete_", "create_", "patch_", "apply_", "save_", "add_", "make_",
                     "rename_", "plan_", "parse_", "import_", "define_", "force_", "revert_", "undo_", "write_")


def _w2_region_calls():
    from tests.test_tools_ida import WORKER_PATH
    source = WORKER_PATH.read_text(encoding="utf-8")
    begin = source.index("# ---- read-only listing operations (W2): begin")
    end = source.index("# ---- read-only listing operations (W2): end")
    first_line = source.count("\n", 0, begin) + 1
    last_line = source.count("\n", 0, end) + 1
    tree = ast.parse(source)
    calls = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and first_line <= node.lineno <= last_line:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    func = sub.func
                    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                    calls.append((node.name, name))
                if isinstance(sub, ast.Attribute) and isinstance(sub.ctx, ast.Store):
                    calls.append((node.name, "store:" + sub.attr))
    return calls


@pytest.mark.contract
def test_the_new_worker_code_makes_no_mutating_call():
    """Every call in the W2 region is a read; no attribute of an IDA object is assigned either."""
    calls = _w2_region_calls()
    assert len(calls) > 200                      # the region was found and parsed, not an empty slice
    bad = [(fn, name) for fn, name in calls if name.startswith(MUTATING_PREFIXES) or name.startswith("store:")]
    assert bad == []


@pytest.mark.contract
def test_the_mutating_prefix_check_would_catch_a_write():
    assert any("set_name".startswith(p) for p in MUTATING_PREFIXES) and any("apply_idasgn_to".startswith(p) for p in MUTATING_PREFIXES)
    assert "plan_to_apply_idasgn".startswith(MUTATING_PREFIXES)


def test_the_listing_operations_are_dispatched_and_listed_in_both_places(worker):
    module, _ida, _db = worker
    for operation in W2_OPERATIONS:
        assert operation in module._OPERATIONS and operation in module._DISPATCH and operation in ti._ALLOWED_OPERATIONS
    assert set(module._OPERATIONS) == set(module._DISPATCH) and set(ti._ALLOWED_OPERATIONS) <= set(module._DISPATCH)


def test_the_listing_operations_that_page_resume_from_a_trimmed_response():
    assert set(W2_OPERATIONS) <= ti._PAGED_OPERATIONS


# ---------------------------------------------------------------------------
# through ida_query (FakeIdat)
# ---------------------------------------------------------------------------
class ListingWrapperTests(IdaCase):
    GOOD = {"disasm_range": "0x1000 8", "basic_blocks": "start", "callgraph": "start", "stack_frame": "start",
            "local_variables": "start", "find_bytes": "48 8B ?? 05", "find_immediate": "0x5A827999",
            "list_structs": "", "get_struct": "_GUID", "flirt_signatures": ""}
    BAD = {"disasm_range": ("0x1000 2001", "INVALID_COUNT"), "basic_blocks": ("", "FUNCTION_REQUIRED"),
           "callgraph": ('{"function": "f", "depth": 5}', "INVALID_DEPTH"), "stack_frame": ("  ", "FUNCTION_REQUIRED"),
           "local_variables": ("x" * 513, "FUNCTION_REQUIRED"), "find_bytes": ("?? ??", "INVALID_PATTERN"),
           "find_immediate": ("-1", "INVALID_VALUE"), "list_structs": ("x" * 257, "INVALID_FILTER"),
           "get_struct": ("", "INVALID_TYPE_NAME"), "flirt_signatures": ("x", "UNEXPECTED_QUERY")}

    def test_every_listing_operation_is_accepted_with_a_good_query(self):
        for operation, query in self.GOOD.items():
            data = self.q(operation, query)
            self.assertTrue(data["ok"], (operation, data))
            self.assertEqual((data["status"], data["operation"]), ("OK", operation))
        self.assertEqual(self.fake.modes[0], "create")      # one analysis, then every question on the cached database
        self.assertEqual(set(self.fake.modes[1:]), {"reopen"})

    def test_a_bad_query_is_refused_before_idat_starts(self):
        for operation, (query, error) in self.BAD.items():
            data = self.q(operation, query)
            self.assertEqual((data["ok"], data["status"], data["error"]), (False, "ANALYSIS_LIMITED", error), operation)
            self.assertIn("Nothing was started", data["detail"])
        self.assertEqual(self.fake.calls, [])

    def test_the_cli_choices_and_the_module_agree_on_the_new_operations(self):
        import liebert_re.cli as cli
        for operation in self.GOOD:
            self.assertIn(operation, cli._IDA_OPERATIONS)

    def test_a_capped_call_graph_is_partial_and_names_the_cap(self):
        self.fake.fields["callgraph"] = dict(root="0x1000", nodes=[{"address": "0x1000"}], node_count=1, max_nodes=1,
                                             nodes_truncated=True, dropped_node_count=3, items=[], total_edge_count=0,
                                             next_offset=None)
        data = self.q("callgraph", "start")
        self.assertEqual(data["status"], "PARTIAL")
        self.assertTrue(any("node cap of 1" in text and "3 further" in text for text in data["limitations"]))

    def test_a_response_cut_to_max_chars_trims_nodes_and_items_and_resumes(self):
        edges = [{"from": hex(0x1000 + i), "to": hex(0x2000 + i), "kind": "direct", "call_count": 1, "call_sites": []}
                 for i in range(300)]
        nodes = [{"address": hex(0x1000 + i), "name": "n%d" % i} for i in range(300)]
        self.fake.fields["callgraph"] = dict(root="0x1000", nodes=nodes, items=edges, total_edge_count=300, offset=0,
                                             next_offset=None, nodes_truncated=False)
        data = self.q("callgraph", "start", max_chars=6000)
        self.assertEqual(data["status"], "PARTIAL")
        self.assertTrue(data["truncated"])
        self.assertLess(len(data["items"]), 300)
        self.assertEqual(data["next_offset"], len(data["items"]))
        self.assertLessEqual(len(json.dumps(data)), 6200)


# ===========================================================================
# "not found" is told apart from "could not look": status / partial / lookup_errors
#
# Every answer carries `status` (OK / NOT_FOUND / UNRESOLVED / QUERY_FAILED), `partial` and a
# `lookup_errors` list. These cases run the worker's `_run` (which sets them) against the same stubs;
# the cases above call the operation functions directly and so see none of the three.
# ===========================================================================
def _status_run(module, operation, query="", max_results=200, offset=0):
    return module._run({"operation": operation, "query": query, "max_results": max_results, "offset": offset,
                        "mode": "idalib"})


def _boom(message="boom"):
    def raiser(*args, **kwargs):
        raise RuntimeError(message)
    return raiser


def _shape(result):
    return result["status"], result["ok"], result["partial"]


# ---- xrefs_to ----
def test_xrefs_to_a_successful_empty_answer_is_not_found(worker):
    module, _ida, db = worker
    db.names["t"] = 0x1100
    r = _status_run(module, "xrefs_to", "t")
    assert _shape(r) == ("NOT_FOUND", True, False) and r["lookup_errors"] == [] and r["items"] == []


def test_xrefs_to_with_references_is_ok_and_not_partial(worker):
    module, _ida, db = worker
    db.names["t"] = 0x1100
    db.refs_to[0x1100] = [_xref(0x1010, 0x1100, 17, True)]
    r = _status_run(module, "xrefs_to", "t")
    assert _shape(r) == ("OK", True, False) and r["lookup_errors"] == []


def test_xrefs_to_an_unresolvable_name_is_unresolved(worker):
    module, _ida, _db = worker
    r = _status_run(module, "xrefs_to", "NoSuchThing")
    assert _shape(r) == ("UNRESOLVED", False, False) and r["error"] == "SYMBOL_NOT_FOUND" and r["lookup_errors"] == []


def test_xrefs_to_a_raising_reference_walk_is_query_failed_never_not_found(worker):
    module, ida, db = worker
    db.names["t"] = 0x1100
    ida["idautils"].XrefsTo.side_effect = _boom("walk died in D:\\scratch\\run\\x.dll")
    r = _status_run(module, "xrefs_to", "t")
    assert (r["status"], r["ok"]) == ("QUERY_FAILED", False) and r["error"] == "LOOKUP_INCOMPLETE"
    assert r["lookup_errors"] == ["XREFS_ENUMERATION_FAILED: RuntimeError: walk died in <path>"]
    assert "scratch" not in json.dumps(r["lookup_errors"])


def test_xrefs_to_one_failing_candidate_leaves_the_other_listed_as_partial(worker):
    module, ida, db = worker
    db.names["Open"] = 0x1500
    db.imports = [("K", "Open", None, 0x4010)]
    db.refs_to[0x1500] = [_xref(0x1010, 0x1500, 17, True)]

    def walk(ea, flags=0):
        if ea == 0x4010:
            raise RuntimeError("slot walk died")
        return iter(db.refs_to.get(ea, []))

    ida["idautils"].XrefsTo.side_effect = walk
    r = _status_run(module, "xrefs_to", "Open")
    assert _shape(r) == ("OK", True, True) and [i["from"] for i in r["items"]] == ["0x1010"]
    assert r["lookup_errors"] == ["XREFS_ENUMERATION_FAILED: RuntimeError: slot walk died"]


def test_xrefs_to_a_name_that_did_not_resolve_because_a_lookup_raised_is_query_failed(worker):
    """The silent-empty bug: a broken import-table walk used to end as a plain "not found"."""
    module, _ida, db = worker
    db.imports = [("K", "x", None, 0x4010)]
    db.import_enum_error = RuntimeError("enum broke")
    r = _status_run(module, "xrefs_to", "target")
    assert _shape(r) == ("QUERY_FAILED", False, False) and r["error"] == "SYMBOL_NOT_FOUND"
    assert r["lookup_errors"] == ["IMPORT_LOOKUP_FAILED: RuntimeError: enum broke"]


def test_xrefs_to_a_missing_demangle_form_is_a_lookup_error_not_a_no_match(worker):
    module, ida, db = worker
    db.names["?Run@@YAXXZ"] = 0x1100
    db.mangled["?Run@@YAXXZ"] = "Run(void)"
    del ida["ida_name"].MNG_SHORT_FORM
    r = _status_run(module, "xrefs_to", "Nope(void)")
    assert r["status"] == "QUERY_FAILED"
    assert any(e.startswith("DEMANGLE_FORM_UNAVAILABLE: AttributeError") for e in r["lookup_errors"])


def test_xrefs_to_an_empty_answer_beside_a_failed_lookup_is_not_a_not_found(worker):
    module, _ida, db = worker
    db.names["target"] = 0x1100
    db.imports = [("K", "x", None, 0x4010)]
    db.import_enum_error = RuntimeError("enum broke")
    r = _status_run(module, "xrefs_to", "target")
    assert (r["status"], r["ok"], r["error"]) == ("QUERY_FAILED", False, "LOOKUP_INCOMPLETE")
    assert r["lookup_errors"] == ["IMPORT_LOOKUP_FAILED: RuntimeError: enum broke"]


def test_xrefs_to_an_unexpected_exception_is_query_failed_with_the_exception_class(worker):
    module, ida, db = worker
    db.names["t"] = 0x1100
    ida["idc"].get_name_ea_simple.side_effect = KeyError("internal")
    r = _status_run(module, "xrefs_to", "t")
    assert (r["status"], r["ok"], r["error"]) == ("QUERY_FAILED", False, "IDAPYTHON_SCRIPT_EXCEPTION")
    assert r["lookup_errors"] == ["QUERY_EXCEPTION: KeyError: 'internal'"] and r["partial"] is False


def test_a_repeated_failure_is_folded_into_one_counted_entry(worker):
    module, ida, db = worker
    db.names["t"] = 0x1100
    db.refs_to[0x1100] = [_xref(0x1000 + i, 0x1100, 17, True) for i in range(3)]
    ida["idautils"].XrefTypeName.side_effect = _boom("no name")
    r = _status_run(module, "xrefs_to", "t")
    assert _shape(r) == ("OK", True, True) and r["lookup_errors"] == ["XREF_TYPE_NAME: RuntimeError: no name (x3)"]
    assert [i["type_name"] for i in r["items"]] == [None, None, None]


# ---- xrefs_from ----
def test_xrefs_from_empty_unresolved_and_failed(worker):
    module, ida, db = worker
    db.names["lone"] = 0x1000
    r = _status_run(module, "xrefs_from", "lone")
    assert _shape(r) == ("NOT_FOUND", True, False)
    assert _shape(_status_run(module, "xrefs_from", "nope")) == ("UNRESOLVED", False, False)
    ida["idautils"].XrefsFrom.side_effect = _boom("from died")
    r = _status_run(module, "xrefs_from", "lone")
    assert (r["status"], r["error"]) == ("QUERY_FAILED", "LOOKUP_INCOMPLETE")
    assert r["lookup_errors"] == ["XREFS_ENUMERATION_FAILED: RuntimeError: from died"]


def test_xrefs_from_a_failed_function_item_walk_falls_back_to_the_address_and_says_so(worker):
    module, ida, db = worker
    _function_with_refs(db)
    db.refs_from[0x1000] = [_xref(0x1000, 0x3000, 1, False)]
    ida["idautils"].FuncItems.side_effect = _boom("items died")
    r = _status_run(module, "xrefs_from", "func")
    assert _shape(r) == ("OK", True, True) and r["scope"] == "address" and [i["to"] for i in r["items"]] == ["0x3000"]
    assert r["lookup_errors"] == ["FUNCITEMS_ENUMERATION_FAILED: RuntimeError: items died"]


# ---- callers_of_import ----
def test_callers_of_import_empty_unresolved_and_failed(worker):
    module, ida, db = worker
    db.imports = [("K", "CreateFileW", None, 0x4010)]
    assert _shape(_status_run(module, "callers_of_import", "CreateFileW")) == ("NOT_FOUND", True, False)
    r = _status_run(module, "callers_of_import", "Nope")
    assert _shape(r) == ("UNRESOLVED", False, False) and r["error"] == "IMPORT_NOT_FOUND"
    ida["idautils"].XrefsTo.side_effect = _boom("callers died")
    r = _status_run(module, "callers_of_import", "CreateFileW")
    assert (r["status"], r["error"]) == ("QUERY_FAILED", "LOOKUP_INCOMPLETE")
    assert r["lookup_errors"] == ["XREFS_ENUMERATION_FAILED: RuntimeError: callers died"]


def test_callers_of_import_a_broken_import_walk_is_query_failed_not_import_not_found(worker):
    module, _ida, db = worker
    db.imports = [("K", "x", None, 0x4010)]
    db.import_enum_error = RuntimeError("enum broke")
    r = _status_run(module, "callers_of_import", "CreateFileW")
    assert (r["status"], r["error"]) == ("QUERY_FAILED", "IMPORT_NOT_FOUND")
    assert r["lookup_errors"] == ["IMPORT_LOOKUP_FAILED: RuntimeError: enum broke"]


# ---- strings ----
class _Str:
    def __init__(self, ea, text):
        self.ea, self.length, self.strtype, self.text = ea, len(text or ""), 0, text

    def __str__(self):
        if self.text is None:
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad byte")
        return self.text


def _strings_world(ida):
    ida["idaapi"].get_fileregion_offset.return_value = 0x200
    ida["ida_nalt"].get_imagebase.return_value = 0x400000


def test_strings_empty_is_not_found_and_a_raising_enumeration_is_query_failed(worker):
    module, ida, _db = worker
    _strings_world(ida)
    ida["idautils"].Strings.side_effect = lambda: iter(())
    r = _status_run(module, "strings", "")
    assert _shape(r) == ("NOT_FOUND", True, False) and r["items_scanned"] == 0
    ida["idautils"].Strings.side_effect = _boom("strings died")
    r = _status_run(module, "strings", "")
    assert (r["status"], r["ok"], r["error"]) == ("QUERY_FAILED", False, "STRINGS_ENUMERATION_FAILED")
    assert r["lookup_errors"] == ["STRINGS_ENUMERATION_FAILED: RuntimeError: strings died"]


def test_strings_a_walk_that_dies_midway_keeps_what_it_read_as_partial(worker):
    module, ida, _db = worker
    _strings_world(ida)

    def listing():
        yield _Str(0x3000, "alpha")
        raise RuntimeError("walk died")

    ida["idautils"].Strings.side_effect = listing
    r = _status_run(module, "strings", "")
    assert _shape(r) == ("OK", True, True) and [i["value"] for i in r["items"]] == ["alpha"]
    assert r["lookup_errors"] == ["STRINGS_ENUMERATION_FAILED: RuntimeError: walk died"]


def test_strings_an_undecodable_entry_has_a_null_value_and_a_lookup_error(worker):
    module, ida, _db = worker
    _strings_world(ida)
    ida["idautils"].Strings.side_effect = lambda: iter([_Str(0x3000, "ok"), _Str(0x3010, None)])
    r = _status_run(module, "strings", "")
    assert _shape(r) == ("OK", True, True) and [i["value"] for i in r["items"]] == ["ok", None]
    assert r["lookup_errors"][0].startswith("STRING_DECODE: UnicodeDecodeError")


def test_strings_a_filter_with_no_match_over_a_clean_walk_is_not_found(worker):
    module, ida, _db = worker
    _strings_world(ida)
    ida["idautils"].Strings.side_effect = lambda: iter([_Str(0x3000, "alpha")])
    r = _status_run(module, "strings", "zzz")
    assert _shape(r) == ("NOT_FOUND", True, False) and r["items_scanned"] == 1


# ---- stack_frame / get_struct / bitfields ----
class _UnreadableMember:
    def __iter__(self):
        raise RuntimeError("udm died")


def test_stack_frame_no_frame_is_not_found_and_an_unknown_function_is_unresolved(w2):
    _frame(w2)
    r = _status_run(w2.module, "stack_frame", "h")
    assert (r["status"], r["error"], r["ok"]) == ("NOT_FOUND", "NO_STACK_FRAME", False)
    assert _shape(_status_run(w2.module, "stack_frame", "nope")) == ("UNRESOLVED", False, False)


def test_stack_frame_a_member_that_cannot_be_read_is_recorded_not_dropped_silently(w2):
    _frame(w2)
    w2.types.frames[0x1000]["members"][1] = _UnreadableMember()
    r = _status_run(w2.module, "stack_frame", "g")
    assert _shape(r) == ("OK", True, True)
    assert [i["name"] for i in r["items"]] == ["var_68", "__saved", "__return_address", "arg_20"]
    assert "STACK_FRAME_MEMBER_UNREADABLE: RuntimeError: udm died" in r["lookup_errors"]   # the fake function also has no frsize etc.


def test_stack_frame_a_member_ida_returns_nothing_for_is_recorded_too(w2):
    _frame(w2)
    base = sys.modules["ida_typeinf"].tinfo_t

    class Tif(base):
        def get_udm(self, index):
            return (-1, None) if index == 0 else super().get_udm(index)

    sys.modules["ida_typeinf"].tinfo_t = Tif
    r = _status_run(w2.module, "stack_frame", "g")
    assert r["partial"] is True and r["total_member_count"] == 4
    assert "STACK_FRAME_MEMBER_UNREADABLE: get_udm returned no member" in r["lookup_errors"]


def test_stack_frame_a_failed_landmark_is_recorded_beside_its_null_region(w2):
    _frame(w2)
    w2.types.landmarks.pop(0x1000)
    r = _status_run(w2.module, "stack_frame", "g")
    assert r["partial"] is True and all(i["region"] is None for i in r["items"])
    assert any(e.startswith("STACK_FRAME_LANDMARK_FRAME_OFF_SAVREGS: KeyError") for e in r["lookup_errors"])


def _raising_bitfield():
    base = sys.modules["ida_typeinf"].tinfo_t

    class Tif(base):
        def get_udm(self, index):
            found, udm = super().get_udm(index)
            udm.is_bitfield = _boom("no bitfield info")
            return found, udm

    sys.modules["ida_typeinf"].tinfo_t = Tif


def test_an_unknown_bitfield_flag_is_null_not_false(w2):
    _types(w2)
    _raising_bitfield()
    r = _status_run(w2.module, "get_struct", "_GUID")
    assert _shape(r) == ("OK", True, True) and [i["is_bitfield"] for i in r["items"]] == [None, None]
    assert r["lookup_errors"] == ["MEMBER_IS_BITFIELD: RuntimeError: no bitfield info (x2)"]


def test_a_known_bitfield_flag_stays_a_bool(w2):
    _types(w2)
    r = _status_run(w2.module, "get_struct", "Flags")
    assert [i["is_bitfield"] for i in r["items"]] == [True, True] and r["partial"] is False


def test_get_struct_not_found_unresolved_and_failed(w2):
    _types(w2)
    assert _shape(_status_run(w2.module, "get_struct", "Nope")) == ("UNRESOLVED", False, False)
    assert _status_run(w2.module, "get_struct", "Color")["status"] == "UNRESOLVED"
    w2.types.named["Empty"] = FakeTypes.type_("Empty", [], size=0)
    assert _shape(_status_run(w2.module, "get_struct", "Empty")) == ("NOT_FOUND", True, False)


# ---- every other query ----
@pytest.mark.parametrize("operation", ["function_at_address", "decompile_function", "stack_frame", "basic_blocks",
                                       "local_variables", "callgraph", "xrefs_from"])
def test_an_internal_exception_is_query_failed_for_every_function_query(w2, operation):
    w2.db.names["g"] = 0x1000
    w2.ida["ida_funcs"].get_func.side_effect = _boom("func lookup died")
    r = _status_run(w2.module, operation, "g")
    assert (r["status"], r["ok"], r["error"]) == ("QUERY_FAILED", False, "IDAPYTHON_SCRIPT_EXCEPTION")
    assert r["lookup_errors"] == ["QUERY_EXCEPTION: RuntimeError: func lookup died"]


@pytest.mark.parametrize("operation, query", [
    ("function_at_address", "nope"), ("decompile_function", "nope"), ("basic_blocks", "nope"),
    ("local_variables", "nope"), ("callgraph", "nope"), ("disasm_range", "0x10 2"), ("read_bytes", "0x10 4"),
    ("find_bytes", '{"pattern": "90", "segment": ".no"}')])
def test_an_unresolvable_target_is_unresolved_for_every_query(w2, operation, query):
    r = _status_run(w2.module, operation, query)
    assert _shape(r) == ("UNRESOLVED", False, False) and r["lookup_errors"] == []


def test_find_bytes_and_find_immediate_empty_are_not_found_and_a_hit_is_ok(w2):
    w2.model.add_insn(0x1000, 2, "nop", data=[0x90, 0x90])
    assert _shape(_status_run(w2.module, "find_bytes", "CC CC")) == ("NOT_FOUND", True, False)
    assert _shape(_status_run(w2.module, "find_bytes", "90 90")) == ("OK", True, False)
    assert _shape(_status_run(w2.module, "find_immediate", "0x1234")) == ("NOT_FOUND", True, False)


def test_listings_that_are_empty_are_not_found(w2):
    w2.ida["idautils"].Functions.side_effect = lambda: iter(())
    assert _shape(_status_run(w2.module, "list_functions")) == ("NOT_FOUND", True, False)
    assert _shape(_status_run(w2.module, "list_structs")) == ("NOT_FOUND", True, False)
    w2.ida["ida_funcs"].get_idasgn_qty.return_value = 0
    assert _shape(_status_run(w2.module, "flirt_signatures")) == ("NOT_FOUND", True, False)


def test_a_page_past_the_end_of_a_non_empty_listing_is_ok_not_not_found(worker):
    module, _ida, db = worker
    db.names["t"] = 0x1100
    db.refs_to[0x1100] = [_xref(0x1010, 0x1100, 17, True)]
    r = _status_run(module, "xrefs_to", "t", offset=5)
    assert _shape(r) == ("OK", True, False) and r["items"] == [] and r["total_xref_count"] == 1


def test_summary_records_a_field_it_could_not_read_instead_of_defaulting_silently(worker):
    module, ida, _db = worker
    ida["ida_hexrays"].init_hexrays_plugin.side_effect = _boom("no decompiler")
    ida["idaapi"].get_kernel_version.side_effect = _boom("no version")
    ida["idautils"].Functions.side_effect = lambda: iter(())
    ida["idautils"].Segments.side_effect = lambda: iter(())
    r = _status_run(module, "summary")
    assert _shape(r) == ("OK", True, True) and r["hexrays_available"] is False and r["ida_kernel_version"] is None
    assert sorted(e.split(":")[0] for e in r["lookup_errors"]) == ["HEXRAYS_PLUGIN_INIT", "KERNEL_VERSION"]


def test_the_unknown_operation_and_a_clean_summary_have_a_status_too(worker):
    module, ida, _db = worker
    ida["idautils"].Functions.side_effect = lambda: iter([0x1000])
    ida["idautils"].Segments.side_effect = lambda: iter([0x1000])
    clean = _status_run(module, "summary")
    assert _shape(clean) == ("OK", True, False) and clean["lookup_errors"] == []
    assert _shape(_status_run(module, "bogus")) == ("QUERY_FAILED", False, False)


def test_the_collector_does_not_leak_from_one_run_into_the_next(worker):
    module, ida, db = worker
    db.names["t"] = 0x1100
    db.refs_to[0x1100] = [_xref(0x1010, 0x1100, 17, True)]
    ida["idautils"].XrefTypeName.side_effect = _boom("no name")
    assert _status_run(module, "xrefs_to", "t")["partial"] is True
    ida["idautils"].XrefTypeName.side_effect = lambda t: "Code_Near_Call"
    again = _status_run(module, "xrefs_to", "t")
    assert (again["partial"], again["lookup_errors"]) == (False, [])


def test_a_long_message_is_cut_and_a_path_in_it_is_replaced():
    module, _ida = _load_worker()
    entry = module._error_entry("STEP", OSError("cannot open /scratch/run/x.i64 because " + "y" * 400))
    assert entry.startswith("STEP: OSError: cannot open <path> because yyy")
    assert len(entry) <= len("STEP: OSError: ") + module._ERROR_MESSAGE_MAX


# ---- the wrapper carries them upward unchanged ----
class QueryStatusWrapperTests(IdaCase):
    def test_the_worker_outcome_is_carried_under_query_result_beside_the_run_status(self):
        self.fake.fields["strings"] = dict(status="NOT_FOUND", partial=False, lookup_errors=[], items_scanned=0,
                                           items_matched=0, offset=0)
        data = self.q("strings", "needle")
        self.assertEqual(data["status"], "OK")                     # the run completed: its status is untouched
        self.assertEqual(data["query_result"], {"status": "NOT_FOUND", "partial": False, "lookup_errors": []})
        self.assertNotIn("partial", data)

    def test_a_partial_lookup_makes_the_run_partial_and_keeps_the_errors_verbatim(self):
        errors = ["IMPORT_LOOKUP_FAILED: RuntimeError: enum broke", "XREF_TYPE_NAME: RuntimeError: no name (x3)"]
        self.fake.fields["xrefs_to"] = dict(status="OK", partial=True, lookup_errors=errors)
        data = self.q("xrefs_to", "start")
        self.assertEqual(data["status"], "PARTIAL")
        self.assertEqual(data["query_result"], {"status": "OK", "partial": True, "lookup_errors": errors})
        self.assertEqual(data["lookup_errors"], errors)
        self.assertTrue(any("2 sub-step(s)" in text for text in data["limitations"]))

    def test_a_worker_refusal_keeps_its_query_status_and_the_run_status_stays_the_wrappers(self):
        sha, md5 = self.sha, self.md5

        def body(job, _sha):
            return {"ok": False, "tool": "ida_query", "operation": job["operation"], "items": [],
                    "error": "SYMBOL_NOT_FOUND", "status": "UNRESOLVED", "partial": False, "lookup_errors": [],
                    "engine_input_sha256": sha, "engine_input_md5": md5, "script_completed": True}

        self.fake._body = body
        data = self.q("xrefs_to", "nothing")
        self.assertEqual((data["ok"], data["status"], data["error"]), (False, "ANALYSIS_LIMITED", "SYMBOL_NOT_FOUND"))
        self.assertEqual(data["query_result"]["status"], "UNRESOLVED")
        self.assertNotIn("partial", data)

    def test_a_result_that_carries_no_status_is_unknown_not_ok(self):
        data = self.q("xrefs_to", "start")
        self.assertEqual(data["query_result"], {"status": "UNKNOWN", "partial": None, "lookup_errors": []})

    def test_the_wrappers_own_failure_paths_are_query_failed(self):
        data = self.q("bogus_operation", "")
        self.assertEqual((data["ok"], data["error"]), (False, "UNKNOWN_OPERATION"))
        self.assertEqual(data["query_result"], {"status": "QUERY_FAILED", "partial": False,
                                                "lookup_errors": ["IDA_QUERY_WRAPPER: UNKNOWN_OPERATION"]})
        self.fake.behaviour = "timeout"
        data = self.q("xrefs_to", "start")
        self.assertEqual((data["ok"], data["status"]), (False, "TIMEOUT"))
        self.assertEqual(data["query_result"]["status"], "QUERY_FAILED")
        self.assertEqual(data["query_result"]["lookup_errors"],
                         ["IDA_QUERY_WRAPPER: IDA_TIMEOUT_PROCESS_TREE_TERMINATED"])
