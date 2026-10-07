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
"""
from __future__ import annotations

import json
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
