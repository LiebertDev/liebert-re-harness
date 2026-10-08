"""emulate_range (liebert_re/recover/emulate.py): bounded Unicorn emulation behind a declared-target-class gate.

Every fixture is built in code: a synthetic PE32+ from ``owned_binary_fixtures.build_owned_pe_sections`` with
bytes patched into ``.text`` (assembled with Keystone, or raw VEX encodings checked against Capstone). No
third-party binary is involved and nothing here emulates a real sample.

What is pinned, in order: a packer-shaped self-decoding image (return to the sentinel, dump equal to the
expected plaintext, ``executed_after_write`` right in both directions), every stop reason the module names,
the import trap, the minimal TEB/PEB, VEX instructions through the layer in ``recover/vex.py``, the gate
(class, hash, registry), the process boundary, a simulated engine crash, and the two ways evidence can fail.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

import capstone
import keystone
import pefile
import pytest

from liebert_re import cli
import liebert_re.recover.emulate as emulate
from liebert_re.recover import owned_binary_fixtures as fixtures
from tests._scratch import process_scratch

REPO_ROOT = Path(__file__).resolve().parent.parent
IMAGE_BASE = 0x140000000
TEXT = IMAGE_BASE + 0x1000          # .text is the first section, RVA 0x1000, raw data at file offset 0x400
RWX = 0xE0000020                    # code | execute | read | write
RX = 0x60000020                     # code | execute | read
SENTINEL = 0x7FEE00000000
_KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

def asm(source, address=TEXT):
    return bytes(_KS.asm(source, address)[0])


@pytest.fixture(autouse=True)
def sandbox(monkeypatch, tmp_path):
    """A scratch root inside the workspace (safe_path refuses the OS temp dir), dumps redirected into it, and a
    home directory of the test's own so the operator registry the gate reads is never the real one."""
    scratch = process_scratch("emulate")
    scratch.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(emulate, "DUMP_ROOT", scratch / "dumps")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    yield scratch
    shutil.rmtree(scratch, ignore_errors=True)


def build(scratch, code=b"", *, name="sample.exe", chars=RWX, imports=None, patches=(), **kwargs):
    """A PE whose .text holds ``code`` (plus ``patches``: (offset-in-.text, bytes) pairs)."""
    path = scratch / name
    fixtures.build_owned_pe_sections(path, sections=((".text", chars),), imports=imports, **kwargs)
    data = bytearray(path.read_bytes())
    for offset, blob in ((0, code), *patches):
        data[0x400 + offset:0x400 + offset + len(blob)] = blob
    path.write_bytes(bytes(data))
    return path


def emulate_json(path, start=TEXT, **kwargs):
    kwargs.setdefault("target_class", "public_crackme")
    return json.loads(emulate.emulate_range(str(path), start, **kwargs))


def dump_bytes(result, name):
    root = emulate.DUMP_ROOT / result["dump"]["input_sha16"] / result["dump"]["run_id"]
    return (root / name).read_bytes()


def section_dump(result, index=0):
    row = result["section_diffs"][index]
    assert row["dump_file"], "the section was not changed, so no dump exists"
    data = dump_bytes(result, row["dump_file"])
    assert hashlib.sha256(data).hexdigest() == row["dump_sha256"]
    return data


# -- a self-decoding image ---------------------------------------------------------------------------------------

PLAIN_TAIL = asm("mov eax, 0x1234; ret", 0)
PAYLOAD_AT = 0x80
KEY = 0x5A


def xor_program():
    """lea/mov/xor-loop/jmp: decrypt six bytes in place, then run them. Instruction count: 2 + 4*6 + 1 + 2."""
    count = len(PLAIN_TAIL)
    code = asm(f"lea rsi, [rip + {PAYLOAD_AT - 7}]; mov ecx, {count}; l: xor byte ptr [rsi], {KEY}; inc rsi; "
               f"dec ecx; jnz l; jmp {TEXT + PAYLOAD_AT}")
    assert len(code) < PAYLOAD_AT
    cipher = bytes(b ^ KEY for b in PLAIN_TAIL)
    return code, cipher


def test_a_self_decoding_image_returns_to_the_sentinel_and_the_dump_is_the_plaintext(sandbox):
    code, cipher = xor_program()
    path = build(sandbox, code, patches=[(PAYLOAD_AT, cipher)])
    result = emulate_json(path)
    assert result["ok"] is True and result["status"] == "OK"
    assert result["stop_reason"] == "RETURNED"
    assert result["stop_detail"] == {"sentinel": hex(SENTINEL), "rax": "0x1234"}
    assert result["registers"]["rax"] == "0x1234"
    assert result["instructions"] == 2 + 4 * len(PLAIN_TAIL) + 1 + 2
    assert result["rip"] == hex(SENTINEL)
    # The dump is the section as it stands after the run: the original code, with the payload decrypted.
    expected = bytearray(0x200)
    expected[:len(code)] = code
    expected[PAYLOAD_AT:PAYLOAD_AT + len(PLAIN_TAIL)] = PLAIN_TAIL
    assert section_dump(result) == bytes(expected)
    row = result["section_diffs"][0]
    assert row["changed_bytes"] == len(PLAIN_TAIL) and row["name"] == ".text"
    assert row["baseline_sha256"] != row["final_sha256"]
    # A dump is raw bytes, not a PE: it must not begin with an MZ header.
    assert section_dump(result)[:2] != b"MZ"
    # The decrypted region was written, and then executed.
    region = result["written_regions"]
    assert region == [{"va": hex(TEXT + PAYLOAD_AT), "size": len(PLAIN_TAIL),
                       "sha256": hashlib.sha256(PLAIN_TAIL).hexdigest(),
                       "executed_after_write": True, "first_executed_va": hex(TEXT + PAYLOAD_AT)}]
    assert result["recent_rips"][-1] == hex(TEXT + PAYLOAD_AT + len(asm("mov eax, 0x1234", 0)))
    assert len(result["recent_rips"]) == min(64, result["instructions"])


def test_a_region_written_but_never_executed_is_not_flagged(sandbox):
    """The flag must say 'executed after the write', not 'executable' or 'written'. Here the code writes a byte
    to a spot nothing ever runs from."""
    code = asm("mov byte ptr [rip + 0x100], 0x41; ret")
    result = emulate_json(build(sandbox, code))
    assert result["stop_reason"] == "RETURNED"
    assert [(r["size"], r["executed_after_write"], r["first_executed_va"]) for r in result["written_regions"]] == [(1, False, None)]


def test_bytes_executed_before_they_are_overwritten_are_not_flagged(sandbox):
    """Order matters: running a byte and then rewriting it is not 'executed after write'."""
    code = asm("nop; mov byte ptr [rip - 8], 0x90; ret")   # rewrites the nop that already ran
    result = emulate_json(build(sandbox, code))
    assert result["stop_reason"] == "RETURNED"
    assert [r["executed_after_write"] for r in result["written_regions"]] == [False]


def test_instruction_rate_is_measured_and_the_count_is_exact_for_a_long_loop(sandbox):
    passes = 150
    data = 0x100
    code = asm(f"mov r8d, {passes}; outer: lea rsi, [rip + {data - 13}]; mov ecx, 100; inner: xor byte ptr [rsi], {KEY}; "
               "inc rsi; dec ecx; jnz inner; dec r8d; jnz outer; ret")
    result = emulate_json(build(sandbox, code), max_instructions=1_000_000)
    assert result["stop_reason"] == "RETURNED"
    assert result["instructions"] == 1 + passes * (2 + 4 * 100 + 2) + 1
    assert isinstance(result["instructions_per_second"], int) and result["instructions_per_second"] > 0
    assert result["elapsed_s"] > 0
    # 150 passes over the same 100 bytes: an even number of XORs restores the original, so nothing differs
    # from the baseline even though every byte was written 150 times.
    assert result["section_diffs"][0]["changed_bytes"] == 0
    assert [(r["size"]) for r in result["written_regions"]] == [100]


# -- the stop reasons ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("source, reason, count, detail", [
    ("mov eax, 0x55; syscall", "SYSCALL", 2, {"instruction": "syscall", "number": "0x55"}),
    ("mov eax, 7; sysenter", "SYSCALL", 2, {"instruction": "sysenter", "number": "0x7"}),
    ("nop; int3", "INT3", 2, {}),
    ("int 0x2e", "INTERRUPT", 1, {"number": 0x2E}),
    ("nop; hlt", "HLT", 2, {}),
    ("nop; ud2", "UD2", 1, {}),
    ("mov dx, 0x60; in al, dx", "PORT_IO", 2, {"direction": "in", "port": "0x60"}),
    ("nop; mov qword ptr [0x1234], rax", "UNMAPPED_WRITE", 1, {"address": "0x1234"}),
    ("nop; mov rax, [0x1234]", "UNMAPPED_READ", 1, {"address": "0x1234"}),
])
def test_each_stop_reason_is_named_with_its_detail_and_the_faulting_instruction_is_not_counted(
        sandbox, source, reason, count, detail):
    result = emulate_json(build(sandbox, asm(source)))
    assert result["ok"] is True and result["stop_reason"] == reason
    for key, value in detail.items():
        assert result["stop_detail"][key] == value
    assert result["instructions"] == count


def test_an_invalid_encoding_is_reported_as_such_and_not_as_ud2(sandbox):
    result = emulate_json(build(sandbox, bytes([0x90, 0x0F, 0xFF, 0xFF])))
    assert result["stop_reason"] == "INVALID_INSTRUCTION" and result["instructions"] == 1


def test_an_infinite_loop_stops_at_exactly_the_instruction_bound(sandbox):
    result = emulate_json(build(sandbox, asm("l: jmp l")), max_instructions=1000)
    assert result["stop_reason"] == "INSN_LIMIT" and result["instructions"] == 1000
    assert result["stop_detail"] == {"limit": 1000}


def test_the_timeout_stops_a_loop_the_instruction_bound_would_not(sandbox):
    result = emulate_json(build(sandbox, asm("l: jmp l")), max_instructions=50_000_000, timeout_s=1)
    assert result["ok"] is True and result["stop_reason"] == "TIMEOUT"
    assert 0 < result["instructions"] < 50_000_000


def test_a_stop_address_stops_before_that_instruction_runs(sandbox):
    result = emulate_json(build(sandbox, asm("inc eax; inc eax; inc eax; inc eax")), stop_at=[TEXT + 4])
    assert result["stop_reason"] == "STOP_ADDRESS" and result["instructions"] == 2
    assert result["registers"]["rax"] == "0x2" and result["rip"] == hex(TEXT + 4)


def test_registers_can_be_set_and_rsp_is_where_the_sentinel_goes(sandbox):
    result = emulate_json(build(sandbox, asm("add rax, rcx; ret")), registers={"rax": 1, "rcx": "0x10"})
    assert result["stop_reason"] == "RETURNED" and result["registers"]["rax"] == "0x11"
    bad = emulate_json(build(sandbox, asm("ret")), registers={"rsp": 0})
    assert bad["status"] == "TOOL_USAGE" and bad["error"] == "BAD_REGISTERS"
    assert emulate_json(build(sandbox, asm("ret")), registers={"cr0": 1})["error"] == "BAD_REGISTERS"


def test_a_write_to_a_section_declared_read_only_stops_and_rwx_mode_is_reported_as_an_approximation(sandbox):
    code = asm("mov byte ptr [rip + 0x20], 1; ret")
    declared = emulate_json(build(sandbox, code, chars=RX))
    assert declared["stop_reason"] == "WRITE_PROTECT" and declared["instructions"] == 0
    assert declared["perm_mode"] == "as_declared"
    assert declared["image"]["sections"][0]["applied"] == "r-x"
    forced = emulate_json(build(sandbox, code, chars=RX), perm_mode="rwx")
    assert forced["stop_reason"] == "RETURNED"
    assert forced["image"]["sections"][0] == {**forced["image"]["sections"][0], "declared": "r-x", "applied": "rwx"}
    assert "APPROXIMATION" in forced["perm_mode_note"]


# -- imports ---------------------------------------------------------------------------------------------------------

def iat_slots(path):
    """The IAT slot addresses, read with pefile (independently of the module under test)."""
    pe = pefile.PE(data=Path(path).read_bytes())   # from bytes: a mapped file could not be rewritten on Windows
    return {imp.name.decode(): imp.address for entry in pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports}


def test_a_call_through_the_iat_stops_with_the_import_named(sandbox):
    imports = {"kernel32.dll": ["ExitProcess", "GetTickCount"]}
    slots = iat_slots(build(sandbox, imports=imports))
    assert slots["GetTickCount"] == slots["ExitProcess"] + 8
    code = asm(f"nop; call qword ptr [rip + {slots['GetTickCount'] - (TEXT + 1 + 6)}]; ret")
    result = emulate_json(build(sandbox, code, imports=imports))
    assert result["stop_reason"] == "IMPORT_CALL"
    assert result["stop_detail"]["import"] == "kernel32.dll!GetTickCount"
    assert result["instructions"] == 2                      # the call itself ran; the callee was never entered
    assert result["image"]["imports"]["status"] == "TRAPPED" and result["image"]["imports"]["slots_trapped"] == 2
    # The return address the call pushed is the instruction after it, so a caller can resume by hand.
    assert result["stop_detail"]["qword_at_rsp"] == hex(TEXT + 7)
    other = emulate_json(build(sandbox, asm(f"call qword ptr [rip + {slots['ExitProcess'] - (TEXT + 6)}]"), imports=imports))
    assert other["stop_detail"]["import"] == "kernel32.dll!ExitProcess"


def test_an_unreadable_import_directory_runs_without_traps_and_says_so(sandbox):
    result = emulate_json(build(sandbox, asm("ret"), bad_import_rva=True))
    assert result["stop_reason"] == "RETURNED"
    imports = result["image"]["imports"]
    assert imports["status"] == "UNREADABLE" and imports["slots_trapped"] == 0 and "NO slot was rewritten" in imports["note"]
    # The run is kept (everything up to a call is a real measurement) but it is marked as weakened: without
    # trapped slots the IMPORT_CALL stop guarantee is gone, and the result must carry that.
    assert [item["code"] for item in result["limitations"]] == ["IMPORT_DIRECTORY_UNREADABLE"]
    assert "IMPORT_CALL" in result["limitations"][0]["detail"]


def test_a_run_with_a_readable_import_directory_has_no_limitations(sandbox):
    assert emulate_json(build(sandbox, asm("ret")))["limitations"] == []
    assert emulate_json(build(sandbox, asm("ret"), imports={"kernel32.dll": ["ExitProcess"]}))["limitations"] == []


# -- completion: whether the routine finished, apart from ok (a result record exists) -----------------------------

def test_completion_names_how_the_routine_ended_while_ok_stays_true(sandbox):
    imports = {"kernel32.dll": ["ExitProcess"]}
    slot = iat_slots(build(sandbox, imports=imports))["ExitProcess"]
    cases = [
        (asm("ret"), {}, "RETURNED"),
        (asm(f"call qword ptr [rip + {slot - (TEXT + 6)}]"), {}, "STOPPED_AT_IMPORT"),
        (asm("syscall"), {}, "STOPPED_AT_SYSCALL"),
        (asm("l: jmp l"), {"max_instructions": 50}, "INSN_LIMIT"),
        (asm("l: jmp l"), {"max_instructions": 50_000_000, "timeout_s": 1}, "TIMEOUT"),
        (asm("mov rax, [0x10]"), {}, "FAULT"),
        (asm("ud2"), {}, "FAULT"),
        (asm("nop; nop"), {"stop_at": [TEXT + 1]}, "UNKNOWN"),     # STOP_ADDRESS is the caller's stop, not a finish
        (asm("int3"), {}, "UNKNOWN"),
    ]
    for code, kwargs, expected in cases:
        result = emulate_json(build(sandbox, code, imports=imports), **kwargs)
        assert result["ok"] is True, result["stop_reason"]
        assert result["completion"] == expected, (result["stop_reason"], result["completion"])
    assert "UNKNOWN" in result["completion_basis"]


def test_every_stop_reason_the_module_names_has_a_completion_that_is_never_a_guess():
    assert emulate._completion(None) is None
    assert emulate._completion("NO_SUCH_STOP") == "UNKNOWN"
    # Only RETURNED may claim the routine finished; a failed run must not read as a finished one.
    assert [k for k, v in emulate._COMPLETION.items() if v == "RETURNED"] == ["RETURNED"]
    for unmapped in ("STOP_ADDRESS", "SENTINEL_REACHED", "INT3", "INTERRUPT", "HLT", "PORT_IO", "UNMODELLED_VEX", "ENGINE_ERROR",
                     "ENGINE_CRASH", "MEMORY_LIMIT", "UNKNOWN_STOP"):
        assert emulate._completion(unmapped) == "UNKNOWN"


def test_reaching_the_sentinel_by_jmp_or_call_is_not_a_return(sandbox):
    """Regression: completion was RETURNED whenever the sentinel was reached. A jmp (or call, or a push+ret that
    leaves the stack unbalanced) into the sentinel is a stop at the sentinel, not a finished routine."""
    for source in (f"mov rax, {SENTINEL}; jmp rax",
                   f"mov rax, {SENTINEL}; call rax",
                   f"mov rax, {SENTINEL}; push rax; ret"):
        result = emulate_json(build(sandbox, asm(source)))
        assert result["ok"] is True, source
        assert result["stop_reason"] == "SENTINEL_REACHED", (source, result["stop_reason"])
        assert result["completion"] == "UNKNOWN", source
        assert result["stop_detail"]["not_verified_because"], source
        assert result["rip"] == hex(SENTINEL)


def test_a_ret_to_the_sentinel_is_still_a_return_with_or_without_prefixes_and_operand(sandbox):
    for source in ("ret", "ret 8", "rep ret", "mov eax, 5; ret"):
        result = emulate_json(build(sandbox, asm(source)))
        assert (result["stop_reason"], result["completion"]) == ("RETURNED", "RETURNED"), source
        assert "not_verified_because" not in result["stop_detail"]
    assert emulate_json(build(sandbox, asm("ret 8")))["registers"]["rsp"] == hex(0x7FFC0000 - 0x100 + 8 + 8 + 8)


def test_ret_check_reports_why_it_cannot_prove_a_return():
    assert emulate._ret_check(b"", 0x1008, 0x1000) == "the last executed instruction could not be read"
    assert emulate._ret_check(b"\xc3", 0x1008, 0x1000) is None
    assert emulate._ret_check(b"\xc2\x10\x00", 0x1018, 0x1000) is None
    assert emulate._ret_check(b"\xc3", 0x1000, 0x1000)                    # popped nothing
    assert emulate._ret_check(b"\xff\xe0", 0x1008, 0x1000)                   # jmp rax
    assert emulate._ret_check(b"\x66\xc3", 0x1008, 0x1000)                  # retw pops 2 bytes, not the sentinel
    assert emulate._ret_check(b"\xc2", 0x1008, 0x1000)                 # truncated operand


def test_a_run_that_never_started_has_no_completion(sandbox):
    refused = emulate_json(build(sandbox, asm("ret")), target_class=None)
    assert refused["status"] == "TARGET_CLASS_REQUIRED" and refused["completion"] is None
    usage = emulate_json(build(sandbox, asm("ret")), registers={"cr0": 1})
    assert usage["error"] == "BAD_REGISTERS" and usage["completion"] is None


def test_a_killed_emulator_process_has_no_state_and_a_completion_that_does_not_claim_a_finish():
    class Outcome:
        launch_failed = False
        resource_limit_unavailable = False
        timed_out = False
        memory_exceeded = True
        process_tree_terminated = True
        returncode = None
        stdout = ""
        stderr = ""

    memory = emulate._Runner.interpret(Outcome, Path("."))
    assert memory["ok"] is False and memory["state_available"] is False
    assert emulate._completion(memory["stop_reason"]) == "UNKNOWN"
    Outcome.memory_exceeded, Outcome.timed_out = False, True
    wall = emulate._Runner.interpret(Outcome, Path("."))
    assert wall["ok"] is False and wall["state_available"] is False and emulate._completion(wall["stop_reason"]) == "TIMEOUT"


# -- the instruction bound at its edge --------------------------------------------------------------------------

def test_the_instruction_bound_refuses_the_next_instruction_and_lets_an_exact_fit_finish(sandbox):
    """Measured behaviour: the bound is checked BEFORE each instruction runs. A routine of exactly N instructions
    with max_instructions=N finishes (RETURNED, instructions == N); with max_instructions=N-1 the Nth instruction
    (the ret) is refused, never executed, and the state is the one after N-1 instructions."""
    code = asm("mov eax, 1; mov ebx, 2; mov ecx, 3; ret")
    after_three = TEXT + len(asm("mov eax, 1; mov ebx, 2; mov ecx, 3", 0))
    exact = emulate_json(build(sandbox, code), max_instructions=4)
    assert exact["stop_reason"] == "RETURNED" and exact["completion"] == "RETURNED" and exact["instructions"] == 4
    assert exact["rip"] == hex(SENTINEL) and exact["registers"]["rcx"] == "0x3"
    short = emulate_json(build(sandbox, code), max_instructions=3)
    assert short["stop_reason"] == "INSN_LIMIT" and short["completion"] == "INSN_LIMIT"
    assert short["instructions"] == 3 and short["stop_detail"] == {"limit": 3}
    assert short["rip"] == hex(after_three)                       # the ret did not run
    assert short["registers"]["rcx"] == "0x3"                     # the third mov did
    assert int(short["registers"]["rsp"], 16) == int(exact["registers"]["rsp"], 16) - 8   # still holds the return address
    fewer = emulate_json(build(sandbox, code), max_instructions=2)
    assert fewer["registers"]["rcx"] == "0x0" and fewer["instructions"] == 2


# -- the TEB / PEB model -------------------------------------------------------------------------------------------------

def test_the_teb_and_peb_fields_that_are_assigned_are_the_ones_declared(sandbox):
    code = asm("mov rax, gs:[0x30]; mov rbx, gs:[0x60]; mov rcx, [rbx + 0x10]; movzx edx, byte ptr [rbx + 2]; "
               "mov rsi, gs:[8]; mov rdi, gs:[0x10]; ret")
    result = emulate_json(build(sandbox, code), stack_size=0x20000)
    model = result["teb_peb_model"]
    assert result["stop_reason"] == "RETURNED"
    assert result["registers"]["rax"] == model["teb_va"] == model["gs_base"]            # TEB.Self
    assert result["registers"]["rbx"] == model["peb_va"]                                 # TEB.ProcessEnvironmentBlock
    assert result["registers"]["rcx"] == hex(IMAGE_BASE)                                 # PEB.ImageBaseAddress
    assert result["registers"]["rdx"] == "0x0"                                           # PEB.BeingDebugged
    assert result["registers"]["rsi"] == model["assigned"]["TEB.NtTib.StackBase"]
    assert result["registers"]["rdi"] == model["assigned"]["TEB.NtTib.StackLimit"]
    assert int(model["assigned"]["TEB.NtTib.StackBase"], 16) - int(model["assigned"]["TEB.NtTib.StackLimit"], 16) == 0x20000
    assert model["assigned"]["PEB.Ldr"] == "NULL" and "not a Windows value" in model["everything_else"]


def test_walking_the_loader_list_stops_because_ldr_is_null(sandbox):
    """PEB.Ldr is NULL by design: reading it succeeds and following it is an unmapped read, never an invented list."""
    result = emulate_json(build(sandbox, asm("mov rax, gs:[0x60]; mov rax, [rax + 0x18]; mov rax, [rax + 0x10]")))
    assert result["stop_reason"] == "UNMAPPED_READ" and result["stop_detail"]["address"] == "0x10"
    assert result["instructions"] == 2 and result["registers"]["rax"] == "0x0"


# -- VEX through the layer in recover/vex.py ---------------------------------------------------------------------------

class Code:
    """Machine code laid out front to back, so every displacement is computed from where it actually lands."""

    def __init__(self):
        self.blob = bytearray()

    @property
    def at(self):
        return len(self.blob)

    def asm(self, source):
        self.blob += asm(source, TEXT + self.at)
        return self

    def raw(self, data):
        self.blob += data
        return self

    def vmovdqu_load(self, reg, target):
        """vmovdqu xmmN, [rip + target]  (VEX.128.F3.0F 6F, RIP-relative)"""
        return self.raw(bytes([0xC5, 0xFA, 0x6F, 0x05 | reg << 3]) + struct.pack("<i", target - (self.at + 8)))

    def vmovdqu_store(self, target, reg):
        """vmovdqu [rip + target], xmmN  (VEX.128.F3.0F 7F)"""
        return self.raw(bytes([0xC5, 0xFA, 0x7F, 0x05 | reg << 3]) + struct.pack("<i", target - (self.at + 8)))

    def pad_to(self, offset):
        assert self.at <= offset, "code ran past %#x" % offset
        return self.raw(bytes([0x90]) * (offset - self.at))


VPADDB_XMM0_XMM0_XMM1 = bytes.fromhex("c5f9fcc1")


def test_vex_encodings_used_below_are_the_instructions_they_claim_to_be():
    code = Code().vmovdqu_load(1, 0x40).raw(VPADDB_XMM0_XMM0_XMM1).vmovdqu_store(0x40, 0)
    shown = [(i.mnemonic, i.op_str) for i in capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64).disasm(bytes(code.blob), 0)]
    assert [m for m, _ in shown] == ["vmovdqu", "vpaddb", "vmovdqu"]
    assert shown[0][1].startswith("xmm1,") and shown[1][1] == "xmm0, xmm0, xmm1" and shown[2][1].endswith("xmm0")


A_BLOCK, B_BLOCK, OUT_BLOCK = bytes(range(16)), bytes(range(0x10, 0x20)), 0x120


def test_a_loop_of_vex_instructions_computes_what_the_instructions_define(sandbox):
    """vpaddb reads its SECOND source; an engine that decodes it as legacy SSE leaves xmm0 = xmm1. A loop adds B
    three times to A, so the right answer differs from the wrong one on every byte."""
    code = Code().vmovdqu_load(0, 0x100).vmovdqu_load(1, 0x110).asm("mov ecx, 3")
    loop = code.at
    code.raw(VPADDB_XMM0_XMM0_XMM1).asm("dec ecx").asm(f"jnz {TEXT + loop}").vmovdqu_store(OUT_BLOCK, 0).asm("ret")
    result = emulate_json(build(sandbox, bytes(code.blob), patches=[(0x100, A_BLOCK), (0x110, B_BLOCK)]))
    assert result["stop_reason"] == "RETURNED" and result["instructions"] == 14
    want = bytes((x + 3 * y) & 0xFF for x, y in zip(A_BLOCK, B_BLOCK))
    assert section_dump(result)[OUT_BLOCK:OUT_BLOCK + 16] == want
    assert want != B_BLOCK                                  # the legacy-SSE misreading would have left B in xmm0
    assert result["vex"]["instructions_executed_by_layer"] == 6
    assert result["vex"]["mnemonics"] == {"vmovdqu": 3, "vpaddb": 3}


def test_a_vex_instruction_the_layer_does_not_model_stops_the_run(sandbox):
    code = asm("nop") + bytes.fromhex("c4e3fd00c11b")          # vpermq ymm0, ymm1, 0x1b: not modelled
    result = emulate_json(build(sandbox, code))
    assert result["stop_reason"] == "UNMODELLED_VEX"
    assert result["stop_detail"] == {"mnemonic": "vpermq", "instruction_va": hex(TEXT + 1)}


def test_vex_code_written_by_the_program_after_the_same_bytes_ran_as_nops_is_decoded_fresh(sandbox):
    """Self-modifying code: the target is called once as four `nop`s, which caches 'not a VEX instruction' at those
    addresses, then rewritten to `vpaddb xmm0, xmm0, xmm1` and called again. A stale decode would run the nops again
    (xmm0 stays A); the right answer is A + B."""
    target = 0x40
    code = Code().vmovdqu_load(0, 0x100).vmovdqu_load(1, 0x110)
    code.asm(f"call {TEXT + target}")
    code.asm("mov dword ptr [rip + %d], 0xC1FCF9C5" % (target - (code.at + 10)))      # c5 f9 fc c1, little-endian
    code.asm(f"call {TEXT + target}").vmovdqu_store(OUT_BLOCK, 0).asm("ret")
    code.pad_to(target).asm("nop; nop; nop; nop; ret")
    result = emulate_json(build(sandbox, bytes(code.blob), patches=[(0x100, A_BLOCK), (0x110, B_BLOCK)]))
    assert result["stop_reason"] == "RETURNED"
    assert section_dump(result)[OUT_BLOCK:OUT_BLOCK + 16] == bytes((x + y) & 0xFF for x, y in zip(A_BLOCK, B_BLOCK))
    assert result["vex"]["mnemonics"] == {"vmovdqu": 3, "vpaddb": 1}
    assert [r["executed_after_write"] for r in result["written_regions"] if r["va"] == hex(TEXT + target)] == [True]


# -- the gate ---------------------------------------------------------------------------------------------------------

def authorization(path, **override):
    sha = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return {"authorized_by": "test operator", "purpose": "unit test of the emulation gate", "sample_sha256": sha, **override}


@pytest.mark.parametrize("value", [None, "", "third_party", "PUBLIC_CRACKME", 7, ["public_crackme"]])
def test_no_declared_class_means_nothing_runs(sandbox, value):
    path = build(sandbox, asm("ret"))
    result = json.loads(emulate.emulate_range(str(path), TEXT, target_class=value))
    assert result["ok"] is False and result["status"] == "TARGET_CLASS_REQUIRED"
    assert result["gate"]["ok"] is False and "stop_reason" not in result
    assert not (emulate.DUMP_ROOT).exists(), "a refused run must not create a dump directory"
    assert result["host_isolation"] == "process boundary; not a sandbox"


def test_the_class_is_required_even_when_everything_else_is_supplied(sandbox):
    path = build(sandbox, asm("ret"))
    result = json.loads(emulate.emulate_range(str(path), TEXT, authorization=authorization(path),
                                              sample_sha256=authorization(path)["sample_sha256"]))
    assert result["status"] == "TARGET_CLASS_REQUIRED"


def test_owned_target_needs_an_authorization_object(sandbox):
    path = build(sandbox, asm("ret"))
    for missing in (None, "not json", [], {"authorized_by": "x", "purpose": ""}, {"purpose": "p", "sample_sha256": "0" * 64}):
        result = emulate_json(path, target_class="owned_target", authorization=missing)
        assert result["status"] in ("AUTHORIZATION_REQUIRED",) and result["ok"] is False, missing
    no_hash = {"authorized_by": "x", "purpose": "p"}
    assert emulate_json(path, target_class="owned_target", authorization=no_hash)["status"] == "SAMPLE_HASH_REQUIRED"
    short = authorization(path, sample_sha256="abc")
    assert emulate_json(path, target_class="owned_target", authorization=short)["status"] == "SAMPLE_HASH_REQUIRED"


def test_owned_target_whose_hash_is_not_the_files_is_refused(sandbox):
    path = build(sandbox, asm("ret"))
    wrong = authorization(path, sample_sha256="0" * 64)
    result = emulate_json(path, target_class="owned_target", authorization=wrong)
    assert result["status"] == "SAMPLE_HASH_MISMATCH" and result["ok"] is False
    assert not emulate.DUMP_ROOT.exists()
    # Two declared hashes that disagree are refused too, whichever is right.
    both = emulate_json(path, target_class="owned_target", authorization=authorization(path), sample_sha256="1" * 64)
    assert both["status"] == "SAMPLE_HASH_MISMATCH"


def test_owned_target_with_a_matching_hash_runs_and_records_who_authorised_it(sandbox):
    path = build(sandbox, asm("mov eax, 7; ret"))
    result = emulate_json(path, target_class="owned_target", authorization=authorization(path))
    assert result["stop_reason"] == "RETURNED" and result["registers"]["rax"] == "0x7"
    assert result["gate"]["authorization"]["authorized_by"] == "test operator"
    assert result["gate"]["declaration_only"] is True
    assert result["input"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_a_public_crackme_may_declare_a_hash_and_it_must_be_right(sandbox):
    path = build(sandbox, asm("ret"))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    assert emulate_json(path, sample_sha256=sha)["stop_reason"] == "RETURNED"
    assert emulate_json(path, sample_sha256="2" * 64)["status"] == "SAMPLE_HASH_MISMATCH"
    assert emulate_json(path, sample_sha256="nonsense")["status"] == "SAMPLE_HASH_REQUIRED"


def test_a_public_crackme_with_no_registry_file_runs_and_says_the_registry_was_not_checked(sandbox):
    result = emulate_json(build(sandbox, asm("ret")))
    assert result["gate"]["registry_checked"] is False and result["gate"]["registry_note"] == "no registry file"


def test_a_public_crackme_whose_name_is_in_the_operator_registry_is_a_class_conflict(sandbox, tmp_path):
    registry = tmp_path / "home" / ".liebert-re"
    registry.mkdir()
    (registry / "targets.txt").write_text("# names of live products, one per line\nunrelated\nzzfakeware.exe\n", encoding="utf-8")
    clash = emulate_json(build(sandbox, asm("ret"), name="ZzFakeware.EXE"))
    assert clash["status"] == "CLASS_CONFLICT" and clash["ok"] is False and clash["gate"]["registry_checked"] is True
    assert "zzfakeware" not in json.dumps(clash).lower(), "the registry entry must not be echoed"
    assert not emulate.DUMP_ROOT.exists()
    clear = emulate_json(build(sandbox, asm("ret"), name="other.exe"))
    assert clear["stop_reason"] == "RETURNED" and clear["gate"]["registry_checked"] is True
    # The conflict check belongs to the public_crackme declaration; an owned target is not looked up.
    owned = build(sandbox, asm("ret"), name="zzfakeware.exe")
    assert emulate_json(owned, target_class="owned_target", authorization=authorization(owned))["stop_reason"] == "RETURNED"


def test_there_is_no_environment_variable_that_opens_the_gate(sandbox, monkeypatch):
    path = build(sandbox, asm("ret"))
    for name in ("LIEBERT_RE_EMULATE", "LIEBERT_RE_DYNAMIC_LAB", "LIEBERT_RE_EMULATION", "LIEBERT_RE_ALLOW_EMULATION"):
        monkeypatch.setenv(name, "authorized")
    result = json.loads(emulate.emulate_range(str(path), TEXT))
    assert result["status"] == "TARGET_CLASS_REQUIRED"
    source = Path(emulate.__file__).read_text(encoding="utf-8")
    assert "os.environ" not in source.split("class _Runner")[0], "the gate must not read the environment"


# -- arguments and refusals -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs, error", [
    ({"max_instructions": 50_000_001}, "BAD_MAX_INSTRUCTIONS"), ({"max_instructions": 0}, "BAD_MAX_INSTRUCTIONS"),
    ({"timeout_s": 601}, "BAD_TIMEOUT"), ({"timeout_s": 0}, "BAD_TIMEOUT"),
    ({"watch_writes": "none"}, "BAD_WATCH_WRITES"), ({"perm_mode": "x"}, "BAD_PERM_MODE"),
    ({"stack_size": 0x1234}, "BAD_STACK_SIZE"), ({"stop_at": ["zz"]}, "BAD_STOP_AT"), ({"stop_at": [TEXT]}, "BAD_STOP_AT"),
])
def test_arguments_outside_the_documented_bounds_are_usage_errors(sandbox, kwargs, error):
    result = emulate_json(build(sandbox, asm("ret")), **kwargs)
    assert result["status"] == "TOOL_USAGE" and result["error"] == error and result["ok"] is False


def test_a_bad_start_address_and_a_missing_file_and_a_path_outside_the_workspace(sandbox, tmp_path):
    path = build(sandbox, asm("ret"))
    assert json.loads(emulate.emulate_range(str(path), "zz", target_class="public_crackme"))["error"] == "BAD_START_VA"
    assert emulate_json(sandbox / "absent.exe")["status"] == "NOT_FOUND"
    outside = tmp_path / "outside.exe"
    outside.write_bytes(path.read_bytes())
    assert emulate_json(outside)["status"] == "PATH_REFUSED"


def test_images_the_tool_cannot_map_are_refused_with_a_reason(sandbox):
    not_pe = sandbox / "plain.bin"
    not_pe.write_bytes(b"hello" * 100)
    assert emulate_json(not_pe)["status"] == "NOT_A_PE"
    path = build(sandbox, asm("ret"))
    data = bytearray(path.read_bytes())
    struct.pack_into("<H", data, 64 + 4, 0x014C)             # machine = i386
    thirty_two = sandbox / "x86.exe"
    thirty_two.write_bytes(bytes(data))
    assert emulate_json(thirty_two)["status"] == "UNSUPPORTED_ARCHITECTURE"
    # An image base that lands on the TEB is a conflict; the image is never relocated.
    data = bytearray(path.read_bytes())
    struct.pack_into("<Q", data, 64 + 24 + 24, 0x7FFD9000)
    clash = sandbox / "clash.exe"
    clash.write_bytes(bytes(data))
    result = emulate_json(clash)
    assert result["status"] == "MAP_CONFLICT" and result["ok"] is False and result["stop_reason"] is None


# -- the process boundary and the failure paths -------------------------------------------------------------------------------

def test_the_engine_runs_in_a_separate_interpreter_and_the_parent_never_loads_it():
    code = ("import sys, liebert_re.recover.emulate as m; "
            "print(sorted(n for n in ('unicorn', 'capstone', 'numpy') if n in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout
    assert out.strip() == "[]"
    command = emulate._Runner.child_command(Path("job.json"))
    assert command[0] == sys.executable and command[1] == "-I"


def test_a_native_crash_of_the_engine_process_is_reported_and_partial_dumps_are_unverified(sandbox, monkeypatch):
    """The crash is simulated by replacing the child command with a process that writes a file and dies."""
    script = ("import os, sys, pathlib; d = pathlib.Path(sys.argv[1]).parent; "
              "(d / 'section00__text.bin').write_bytes(b'cut short'); os._exit(7)")
    monkeypatch.setattr(emulate._Runner, "child_command", staticmethod(lambda job: [sys.executable, "-c", script, str(job)]))
    result = emulate_json(build(sandbox, asm("ret")))
    assert result["ok"] is False and result["status"] == "ANALYSIS_LIMITED" and result["error"] == "ENGINE_CRASH"
    assert result["stop_reason"] == "ENGINE_CRASH" and result["state_available"] is False
    assert result["emulator_exit_code"] == 7
    assert result["partial_dumps"] == [{"file": "section00__text.bin", "size": 9,
                                        "sha256": hashlib.sha256(b"cut short").hexdigest(), "unverified": True}]
    assert "instructions" not in result and "registers" not in result
    root = emulate.DUMP_ROOT / result["dump"]["input_sha16"] / result["dump"]["run_id"]
    assert not (root / "input.bin").exists() and not (root / "job.json").exists(), "staged input is removed"


def test_a_child_that_prints_garbage_is_a_crash_not_a_result(sandbox, monkeypatch):
    monkeypatch.setattr(emulate._Runner, "child_command",
                        staticmethod(lambda job: [sys.executable, "-c", "print('not json')", str(job)]))
    result = emulate_json(build(sandbox, asm("ret")))
    assert result["error"] == "ENGINE_CRASH" and result["emulator_exit_code"] == 0


def test_the_wall_clock_bound_kills_a_child_that_never_answers(sandbox, monkeypatch):
    monkeypatch.setattr(emulate, "WALL_GRACE_SECONDS", 0)
    monkeypatch.setattr(emulate._Runner, "child_command",
                        staticmethod(lambda job: [sys.executable, "-c", "import time; time.sleep(60)", str(job)]))
    result = emulate_json(build(sandbox, asm("ret")), timeout_s=1)
    assert result["status"] == "TIMEOUT" and result["stop_reason"] == "TIMEOUT" and result["state_available"] is False


def test_an_interpreter_that_cannot_be_started_is_unlaunchable_not_a_finding(sandbox, monkeypatch):
    monkeypatch.setattr(emulate._Runner, "child_command", staticmethod(lambda job: [str(sandbox / "no-such-interpreter")]))
    result = emulate_json(build(sandbox, asm("ret")))
    assert result["ok"] is False and result["status"] == "TOOL_UNLAUNCHABLE" and result["operation_ran"] is False
    assert "stop_reason" not in result


def test_a_host_that_cannot_enforce_the_memory_limit_runs_nothing(sandbox, monkeypatch):
    import liebert_re.bounded_subprocess as bounded
    monkeypatch.setattr(bounded, "_memory_monitor_usable", lambda: False)
    result = emulate_json(build(sandbox, asm("ret")))
    assert result["status"] == "RESOURCE_LIMIT_UNAVAILABLE" and result["ok"] is False and result["operation_ran"] is False


def test_a_gate_record_that_cannot_be_written_stops_the_run_before_it_starts(sandbox, monkeypatch):
    monkeypatch.setattr(emulate._Ledger, "write", staticmethod(lambda name, record: {"type": "OSError", "errno": 13, "strerror": "denied"}))
    result = emulate_json(build(sandbox, asm("ret")))
    assert result["status"] == "ANALYSIS_LIMITED" and result["error"] == "GATE_EVIDENCE_UNWRITABLE"
    assert result["operation_ran"] is False and "stop_reason" not in result
    assert not emulate.DUMP_ROOT.exists()


def test_a_final_record_that_cannot_be_written_withholds_the_result(sandbox, monkeypatch):
    real = emulate._Ledger.write
    calls = []

    def second_write_fails(name, record):
        calls.append(name)
        if len(calls) == 1:
            return real(name, record)
        return {"type": "OSError", "errno": 28, "strerror": "no space left on device"}

    monkeypatch.setattr(emulate._Ledger, "write", staticmethod(second_write_fails))
    code, cipher = xor_program()
    result = emulate_json(build(sandbox, code, patches=[(PAYLOAD_AT, cipher)]))
    assert result["status"] == "EVIDENCE_FINALIZE_FAILED" and result["ok"] is False
    assert result["result_withheld"] is True and result["operation_ran"] is True and result["dumps_retained"] is True
    for withheld in ("stop_reason", "registers", "instructions", "written_regions", "section_diffs"):
        assert withheld not in result
    assert len(calls) == 2


# -- evidence and what a response may contain ------------------------------------------------------------------------------------

def test_the_evidence_record_holds_the_gate_the_result_and_no_path(sandbox):
    code, cipher = xor_program()
    path = build(sandbox, code, patches=[(PAYLOAD_AT, cipher)], name="evidence-name-probe.exe")
    result = emulate_json(path)
    records = sorted(emulate.EVIDENCE.glob("*.json"))
    assert [r.name for r in records] == [result["evidence_name"]]
    record = json.loads(records[0].read_text(encoding="utf-8"))
    assert record["result"]["stop_reason"] == "RETURNED" and record["gate"]["status"] == "GATE_PASSED"
    assert record["input"] == {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size, "name_omitted": True}
    for text in (json.dumps(result), records[0].read_text(encoding="utf-8")):
        assert str(REPO_ROOT) not in text and str(sandbox) not in text and "evidence-name-probe" not in text
        # json.dumps escapes a Windows path separator as a doubled backslash; the only backslashes a clean record
        # may carry are the \n and \" escapes, so once those are removed none may be left.
        assert "\\" not in text.replace("\\n", "").replace('\\"', "")
    assert result["dump"]["location"] == "dataset/emulation/<input_sha16>/<run_id>/"
    assert result["host_isolation"] == "process boundary; not a sandbox"
    assert result["limits"]


def test_a_refusal_is_recorded_too(sandbox):
    result = json.loads(emulate.emulate_range(str(build(sandbox, asm("ret"))), TEXT))
    assert result["evidence_write_error"] is None
    record = json.loads((emulate.EVIDENCE / result["evidence_name"]).read_text(encoding="utf-8"))
    assert record["status"] == "TARGET_CLASS_REQUIRED" and "result" not in record


def test_the_dump_directory_is_keyed_by_input_hash_and_run(sandbox):
    path = build(sandbox, asm("mov byte ptr [rip + 0x100], 1; ret"))
    first, second = emulate_json(path), emulate_json(path)
    assert first["dump"]["input_sha16"] == second["dump"]["input_sha16"] == hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    assert first["dump"]["run_id"] != second["dump"]["run_id"]
    assert (emulate.DUMP_ROOT / first["dump"]["input_sha16"] / first["dump"]["run_id"] / first["section_diffs"][0]["dump_file"]).is_file()


def test_dataset_is_ignored_by_git():
    out = subprocess.run(["git", "check-ignore", "dataset/emulation/x/y/z.bin", "dataset/evidence/emulate_range/x.json"],
                         cwd=REPO_ROOT, capture_output=True, text=True)
    if out.returncode == 128:
        pytest.skip("not a git checkout")
    assert out.stdout.split() == ["dataset/emulation/x/y/z.bin", "dataset/evidence/emulate_range/x.json"]


# -- reaching it from the command line ------------------------------------------------------------------------------------------------------

def _relative(path):
    import os
    return os.path.relpath(path, REPO_ROOT)


def run_cli(capsys, *argv):
    code = cli.main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def test_the_emulate_subcommand_runs_a_range_and_a_refusal_exits_three(sandbox, capsys):
    path = build(sandbox, asm("mov eax, 9; ret"))
    code, out = run_cli(capsys, "emulate", _relative(path), "--start", hex(TEXT), "--target-class", "public_crackme")
    assert code == 0 and out["command"] == "emulate" and out["stop_reason"] == "RETURNED" and out["registers"]["rax"] == "0x9"
    code, out = run_cli(capsys, "emulate", _relative(path), "--start", hex(TEXT))
    assert code == 3 and out["status"] == "TARGET_CLASS_REQUIRED"


def test_the_emulate_subcommand_carries_the_owned_target_authorization(sandbox, capsys):
    path = build(sandbox, asm("nop; nop; ret"))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    base = ["emulate", _relative(path), "--start", hex(TEXT), "--target-class", "owned_target",
            "--authorized-by", "test operator", "--purpose", "cli test"]
    code, out = run_cli(capsys, *base, "--sha256", sha, "--stop-at", hex(TEXT + 1), "--max-instructions", "10", "--reg", "rax=5")
    assert code == 0 and out["stop_reason"] == "STOP_ADDRESS" and out["registers"]["rax"] == "0x5"
    code, out = run_cli(capsys, *base, "--sha256", "0" * 64)
    assert code == 3 and out["status"] == "SAMPLE_HASH_MISMATCH"
    code, out = run_cli(capsys, "emulate", _relative(path), "--start", hex(TEXT), "--target-class", "third_party")
    assert code == 3 and out["status"] == "TARGET_CLASS_REQUIRED"


def test_tool_run_reaches_emulate_range(sandbox, capsys):
    path = build(sandbox, asm("ret"))
    args = json.dumps({"path": _relative(path), "start_va": hex(TEXT), "target_class": "public_crackme"})
    code, out = run_cli(capsys, "tool", "run", "emulate_range", "--args", args)
    assert code == 0 and out["stop_reason"] == "RETURNED"
    code, out = run_cli(capsys, "tool", "describe", "emulate_range")
    assert code == 0 and out["module"] == "liebert_re.recover.emulate" and out["python_only"] is None
    assert {p["name"] for p in out["parameters"] if p["required"]} == {"path", "start_va"}


# -- declarative API stubs: off by default, an allow-list opens them, every answer is an assumption -------------------------------------------

STUB_IMPORTS = {"kernel32.dll": ["ExitProcess", "GetTickCount", "GetTickCount64", "GetLastError", "SetLastError",
                                 "VirtualAlloc", "HeapAlloc", "lstrlenA", "lstrlenW"],
                "user32.dll": ["MessageBeep"]}
STRING_AT = 0x100


def program(sandbox, *steps, imports=STUB_IMPORTS, patches=()):
    """A PE running ``steps``: an assembly string, ``"@Name"`` (call through the IAT slot of ``Name``) or
    ``("data", reg, offset)`` (point ``reg`` at .text+offset). Returns the path."""
    slots = iat_slots(build(sandbox, imports=imports))
    code = b""
    for step in steps:
        here = TEXT + len(code)
        if isinstance(step, tuple):
            code += asm(f"lea {step[1]}, [rip + {TEXT + step[2] - (here + 7)}]", here)
        elif step.startswith("@"):
            code += asm(f"call qword ptr [rip + {slots[step[1:]] - (here + 6)}]", here)
        else:
            code += asm(step, here)
    assert len(code) < STRING_AT
    return build(sandbox, code, imports=imports, patches=patches)


def test_stubs_are_off_unless_the_caller_lists_them(sandbox):
    path = program(sandbox, "@GetTickCount", "ret")
    for kwargs in ({}, {"allow_stubs": []}, {"allow_stubs": None}):
        result = emulate_json(path, **kwargs)
        assert result["stop_reason"] == "IMPORT_CALL" and result["completion"] == "STOPPED_AT_IMPORT"
        assert result["stop_detail"]["import"] == "kernel32.dll!GetTickCount"
        assert result["stubs"]["allowed"] == [] and result["stubs"]["calls"] == [] and result["stubs"]["applied"] is False
        assert result["limitations"] == []


def test_a_listed_stub_answers_with_the_supplied_value_and_leaves_an_assumed_trace_entry(sandbox):
    path = program(sandbox, "@GetTickCount", "mov rbx, rax", "@GetTickCount", "ret")
    result = emulate_json(path, allow_stubs=["GetTickCount"], stub_options={"tick_count": 0x1_2345_6789})
    assert result["stop_reason"] == "RETURNED" and result["completion"] == "RETURNED"
    assert result["registers"]["rax"] == "0x23456789" == result["registers"]["rbx"]       # a DWORD: the low 32 bits
    calls = result["stubs"]["calls"]
    assert len(calls) == 2 and result["stubs"]["calls_total"] == 2 and result["stubs"]["applied"] is True
    first = calls[0]
    assert {k: first[k] for k in ("import", "stubbed", "basis", "args", "ret")} == {
        "import": "kernel32.dll!GetTickCount", "stubbed": True, "basis": "assumed", "args": [], "ret": "0x23456789"}
    assert calls[1]["ret"] == first["ret"] and [c["seq"] for c in calls] == [1, 2]       # fixed: the same every time
    notes = [item for item in result["limitations"] if item["code"] == "STUBBED_IMPORTS"]
    assert len(notes) == 1 and "stubbed imports influenced the run" in notes[0]["detail"]
    assert "assumption" in result["stubs"]["basis"]
    assert result["request"]["allow_stubs"] == ["GetTickCount"]
    assert result["request"]["stub_options"] == {"tick_count": 0x123456789}
    assert result["instructions"] == 4                  # the call into a stub is an instruction; the stub is not


def test_the_64_bit_tick_count_is_not_truncated(sandbox):
    path = program(sandbox, "@GetTickCount64", "ret")
    result = emulate_json(path, allow_stubs=["GetTickCount64"], stub_options={"tick_count": 0x1_0000_0005})
    assert result["registers"]["rax"] == "0x100000005" and result["completion"] == "RETURNED"


def test_set_and_get_last_error_follow_the_windows_x64_convention(sandbox):
    path = program(sandbox, "@GetLastError", "mov rbx, rax", "mov rcx, 0x100000057", "@SetLastError",
                   "@GetLastError", "ret")
    result = emulate_json(path, allow_stubs=["GetLastError", "SetLastError"])
    assert result["completion"] == "RETURNED"
    assert result["registers"]["rbx"] == "0x0" and result["registers"]["rax"] == "0x57"      # the DWORD argument only
    calls = result["stubs"]["calls"]
    assert [c["import"].split("!")[1] for c in calls] == ["GetLastError", "SetLastError", "GetLastError"]
    assert calls[1]["args"] == ["0x57"] and calls[1]["ret"] is None            # void: nothing is returned or written
    assert result["stubs"]["last_error"] == 0x57


def test_an_import_outside_the_allow_list_or_in_another_dll_still_stops_the_run(sandbox):
    path = program(sandbox, "@GetTickCount", "@ExitProcess", "ret")
    result = emulate_json(path, allow_stubs=["GetTickCount"], stub_options={"tick_count": 1})
    assert result["stop_reason"] == "IMPORT_CALL" and result["stop_detail"]["import"] == "kernel32.dll!ExitProcess"
    assert [c["import"] for c in result["stubs"]["calls"]] == ["kernel32.dll!GetTickCount"]
    other = program(sandbox, "@MessageBeep", "ret")
    assert emulate_json(other, allow_stubs=["GetTickCount"], stub_options={"tick_count": 1})["stop_reason"] == "IMPORT_CALL"
    # A same-named import from another DLL is not the kernel32 function the stub models.
    lookalike = program(sandbox, "@GetTickCount", "ret", imports={"user32.dll": ["GetTickCount"]})
    result = emulate_json(lookalike, allow_stubs=["GetTickCount"], stub_options={"tick_count": 1})
    assert result["stop_reason"] == "IMPORT_CALL" and result["stubs"]["applied"] is False and result["limitations"] == []


def test_a_name_with_no_stub_or_a_missing_option_is_a_usage_error_and_nothing_runs(sandbox):
    path = program(sandbox, "ret")
    for kwargs, error in (({"allow_stubs": ["ExitProcess"]}, "BAD_STUBS"),
                          ({"allow_stubs": "GetTickCount"}, "BAD_STUBS"),
                          ({"allow_stubs": [7]}, "BAD_STUBS"),
                          ({"allow_stubs": ["GetTickCount"]}, "BAD_STUB_OPTIONS"),
                          ({"allow_stubs": ["GetLastError"], "stub_options": {"colour": 1}}, "BAD_STUB_OPTIONS"),
                          ({"allow_stubs": ["HeapAlloc"], "stub_options": {"heap_bytes": 0x1800}}, "BAD_STUB_OPTIONS"),
                          ({"stub_options": {"tick_count": 1}}, "BAD_STUB_OPTIONS")):
        result = emulate_json(path, **kwargs)
        assert result["status"] == "TOOL_USAGE" and result["error"] == error and result["completion"] is None, kwargs


def test_heap_alloc_hands_out_distinct_zeroed_aligned_blocks_from_a_bounded_region(sandbox):
    path = program(sandbox, "mov edx, 8", "mov r8d, 20", "@HeapAlloc", "mov rbx, rax",
                   "mov qword ptr [rbx], 0x41", "mov r8d, 1", "@HeapAlloc", "mov rsi, qword ptr [rbx + 8]", "ret")
    result = emulate_json(path, allow_stubs=["HeapAlloc"], watch_writes="all")
    assert result["completion"] == "RETURNED", result["stop_detail"]
    first, second = (int(c["ret"], 16) for c in result["stubs"]["calls"])
    heap = int(result["stubs"]["heap"]["va"], 16)
    assert first == heap and second == heap + 32 and first % 16 == 0 and second % 16 == 0   # 20 rounds up to 32
    assert result["registers"]["rsi"] == "0x0" and result["registers"]["rax"] == hex(second)
    assert result["stubs"]["calls"][0]["args"] == ["0x0", "0x8", "0x14"]
    assert result["stubs"]["calls"][0]["effects"] == [{"kind": "alloc", "va": hex(first), "size": 32, "zero_filled": True}]
    assert result["stubs"]["heap"]["used"] == 48 and result["stubs"]["heap"]["size"] == 0x100000
    assert any(r["va"] == hex(first) for r in result["written_regions"])               # the program's own write is still seen


def test_allocations_count_against_the_bounded_region_and_the_run_stops_when_it_is_full(sandbox):
    path = program(sandbox, "mov r8d, 0x1000", "@HeapAlloc", "mov rbx, rax", "@HeapAlloc", "mov r12, rax",
                   "@HeapAlloc", "mov r13, rax", "ret")
    result = emulate_json(path, allow_stubs=["HeapAlloc"], stub_options={"heap_bytes": 0x2000})
    assert result["stop_reason"] == "STUB_LIMIT" and result["completion"] == "STOPPED_AT_IMPORT"
    assert result["stop_detail"]["import"] == "kernel32.dll!HeapAlloc" and "cannot hold" in result["stop_detail"]["why"]
    assert result["stubs"]["calls_total"] == 2 and result["stubs"]["heap"] == {
        "va": hex(0x7FED00000000), "size": 0x2000, "used": 0x2000}
    assert result["registers"]["r13"] == "0x0" and result["registers"]["r12"] == result["stubs"]["calls"][1]["ret"]
    assert result["rip"] == result["stop_detail"]["trap_va"]       # the refused call was not applied or skipped


def test_virtual_alloc_is_64k_aligned_honours_the_protection_and_refuses_what_it_does_not_model(sandbox):
    read_only = program(sandbox, "xor ecx, ecx", "mov edx, 0x1800", "mov r8d, 0x3000", "mov r9d, 2", "@VirtualAlloc",
                        "mov rbx, rax", "mov qword ptr [rbx], 1", "ret")
    result = emulate_json(read_only, allow_stubs=["VirtualAlloc"])
    base = int(result["stubs"]["calls"][0]["ret"], 16)
    assert base == 0x7FED00000000 and result["stubs"]["calls"][0]["effects"][0]["size"] == 0x2000
    assert result["stop_reason"] == "WRITE_PROTECT" and result["completion"] == "FAULT"
    two = program(sandbox, "xor ecx, ecx", "mov edx, 0x10", "mov r8d, 0x1000", "mov r9d, 4", "@VirtualAlloc",
                  "mov rbx, rax", "@VirtualAlloc", "mov qword ptr [rax + 8], 7", "ret")
    result = emulate_json(two, allow_stubs=["VirtualAlloc"])
    assert result["completion"] == "RETURNED"
    first, second = (int(c["ret"], 16) for c in result["stubs"]["calls"])
    assert (first, second) == (0x7FED00000000, 0x7FED00010000)
    base_steps = {"rcx": "xor ecx, ecx", "rdx": "mov edx, 0x10", "r8": "mov r8d, 0x1000", "r9": "mov r9d, 4"}
    for reg, setup, why in (("rcx", "mov ecx, 0x10000", "non-NULL lpAddress"), ("rdx", "xor edx, edx", "dwSize"),
                            ("r8", "mov r8d, 0x2000", "flAllocationType"), ("r9", "mov r9d, 0x104", "flProtect")):
        steps = [setup if key == reg else step for key, step in base_steps.items()]
        refused = emulate_json(program(sandbox, *steps, "@VirtualAlloc", "ret"), allow_stubs=["VirtualAlloc"])
        assert refused["stop_reason"] == "STUB_LIMIT" and why in refused["stop_detail"]["why"], (reg, refused["stop_reason"])
        assert refused["stubs"]["calls"] == [] and refused["limitations"] == []             # nothing was applied


def test_lstrlen_counts_narrow_and_wide_strings_and_stops_on_a_string_it_cannot_read(sandbox):
    patches = [(STRING_AT, b"hello\0"), (STRING_AT + 0x20, "héllo!".encode("utf-16-le") + b"\0\0")]
    path = program(sandbox, ("data", "rcx", STRING_AT), "@lstrlenA", "mov rbx, rax",
                   ("data", "rcx", STRING_AT + 0x20), "@lstrlenW", "mov rsi, rax", "xor ecx, ecx", "@lstrlenA", "ret",
                   patches=patches)
    result = emulate_json(path, allow_stubs=["lstrlenA", "lstrlenW"])
    assert result["completion"] == "RETURNED"
    assert (result["registers"]["rbx"], result["registers"]["rsi"], result["registers"]["rax"]) == ("0x5", "0x6", "0x0")
    assert result["stubs"]["calls"][0]["effects"] == [{"kind": "read", "va": hex(TEXT + STRING_AT), "bytes": 5}]
    bad = program(sandbox, "mov ecx, 0x10", "@lstrlenA", "ret")
    refused = emulate_json(bad, allow_stubs=["lstrlenA"])
    assert refused["stop_reason"] == "STUB_LIMIT" and "not readable" in refused["stop_detail"]["why"]
    # Non-zero bytes right up to the end of the mapped stack: no terminator, then unmapped memory. A stop, not a length.
    open_ended = program(sandbox, "mov rcx, 0x7FFBFFF0", "mov rax, -1", "mov qword ptr [rcx], rax",
                         "mov qword ptr [rcx + 8], rax", "@lstrlenA", "ret")
    stopped = emulate_json(open_ended, allow_stubs=["lstrlenA"])
    assert stopped["stop_reason"] == "STUB_LIMIT" and stopped["stubs"]["calls"] == []


def test_the_trace_is_bounded_and_a_full_trace_stops_instead_of_dropping_calls(sandbox):
    path = program(sandbox, "mov ebx, 1005", "@GetLastError", "dec ebx", f"jnz {TEXT + 5}", "ret")
    result = emulate_json(path, allow_stubs=["GetLastError"], max_instructions=50_000)
    assert result["stop_reason"] == "STUB_LIMIT" and "trace is full" in result["stop_detail"]["why"]
    assert result["stubs"]["calls_total"] == len(result["stubs"]["calls"]) == 1000
    assert result["registers"]["rbx"] == hex(1005 - 1000)


def test_the_instruction_bound_still_applies_across_stub_calls(sandbox):
    path = program(sandbox, "@GetLastError", f"jmp {TEXT}")
    result = emulate_json(path, allow_stubs=["GetLastError"], max_instructions=100)
    assert result["stop_reason"] == "INSN_LIMIT" and result["instructions"] == 100
    assert result["stubs"]["calls_total"] == 50


def test_a_32_bit_image_is_refused_even_with_stubs_listed(sandbox):
    path = build(sandbox, asm("ret"))
    data = bytearray(path.read_bytes())
    struct.pack_into("<H", data, 64 + 4, 0x014C)
    x86 = sandbox / "x86.exe"
    x86.write_bytes(bytes(data))
    result = emulate_json(x86, allow_stubs=["GetLastError"])
    assert result["status"] == "UNSUPPORTED_ARCHITECTURE" and result["completion"] is None


def test_the_emulate_subcommand_takes_repeatable_allow_stub_flags(sandbox, capsys):
    path = program(sandbox, "@GetTickCount", "mov rbx, rax", "@GetLastError", "ret")
    base = ["emulate", _relative(path), "--start", hex(TEXT), "--target-class", "public_crackme"]
    code, out = run_cli(capsys, *base, "--allow-stub", "GetTickCount", "--allow-stub", "GetLastError",
                        "--stub-tick-count", "0x4d2")
    assert code == 0 and out["completion"] == "RETURNED" and out["registers"]["rbx"] == "0x4d2"
    assert out["stubs"]["allowed"] == ["GetLastError", "GetTickCount"] and out["stubs"]["calls_total"] == 2
    code, out = run_cli(capsys, *base)
    assert code == 0 and out["stop_reason"] == "IMPORT_CALL"
    code, out = run_cli(capsys, *base, "--allow-stub", "GetTickCount")
    assert code != 0 and out["error"] == "BAD_STUB_OPTIONS"


# -- the stub path honours the absolute deadline and its own scan bound -------------------------------------------------------------

def run_in_process(path, start=TEXT, *, timeout_s=5, max_instructions=100_000, **options):
    """The engine run directly in this process (no child), for tests that must control the clock the engine reads."""
    params, bad = emulate._Runner.validate(start, (), max_instructions, timeout_s, "image", None, 0x100000,
                                           "as_declared", **options)
    assert bad is None, bad
    data = Path(path).read_bytes()
    run_dir = emulate.DUMP_ROOT / "in_process" / str(len(list((emulate.DUMP_ROOT).glob("in_process/*"))))
    run_dir.mkdir(parents=True)
    (run_dir / "input.bin").write_bytes(data)
    job = dict(params, input_sha256=hashlib.sha256(data).hexdigest(), dump_dir=str(run_dir), input_file="input.bin")
    return emulate._Engine(job).run()


class RecordingMemory:
    """A stand-in for the engine's memory: non-zero bytes everywhere, optionally a terminator at one byte offset."""

    def __init__(self, terminator_at=None):
        self.base, self.terminator_at, self.reads = None, terminator_at, []

    def mem_read(self, address, size):
        self.base = address if self.base is None else self.base
        self.reads.append((address, size))
        data = bytearray(b"A" * size)
        if self.terminator_at is not None:
            for k in range(size):
                if address + k - self.base == self.terminator_at:
                    data[k:k + 2] = b"\x00\x00"[:min(2, size - k)]
                    break
        return bytes(data)


def test_a_stub_that_returns_after_the_deadline_is_a_timeout_not_a_return(sandbox, monkeypatch):
    """The clock jumps past the deadline while the stub is applied. Resuming would run the final ret and report
    RETURNED; the deadline has to be checked after the stub, before the stop is classified."""
    path = program(sandbox, "@GetLastError", "ret")
    skew, real = [0.0], time.monotonic
    original = emulate._StubBook.apply

    def slow_apply(self, label, name):
        answered = original(self, label, name)
        skew[0] = 1e6
        return answered

    monkeypatch.setattr(time, "monotonic", lambda: real() + skew[0])
    monkeypatch.setattr(emulate._StubBook, "apply", slow_apply)
    result = run_in_process(path, allow_stubs=["GetLastError"])
    assert result["stop_reason"] == "TIMEOUT" and result["completion"] == "TIMEOUT"
    assert result["stop_detail"]["enforced_by"] == "stub apply" and result["stop_detail"]["stub_applied"] is True
    assert result["stubs"]["calls_total"] == 1 and result["registers"]["rax"] != hex(SENTINEL)
    skew[0] = 0.0
    monkeypatch.setattr(emulate._StubBook, "apply", original)
    fast = run_in_process(path, allow_stubs=["GetLastError"])      # the same program inside its time is a return
    assert fast["stop_reason"] == "RETURNED"


def test_a_long_string_scan_stops_at_the_deadline_without_applying_the_stub():
    ticks = iter(range(100))
    book = emulate._StubBook(RecordingMemory(), None, ["lstrlenA"], {})
    book.deadline, book.clock = 3, lambda: next(ticks)
    with pytest.raises(emulate._StubTimeout):
        book._strlen(0x10000, 1)
    assert 1 <= len(book.uc.reads) <= 3 and book.calls == []


def test_a_string_scan_never_reads_past_the_unit_bound_whatever_the_alignment():
    limit = emulate.MAX_STRLEN_UNITS
    for unit, pointer in ((1, 0x10000), (1, 0x10001), (1, 0x10FFF), (2, 0x10002), (2, 0x10FFE)):
        memory = RecordingMemory()
        with pytest.raises(emulate._StubStop, match="no terminator"):
            emulate._StubBook(memory, None, ["lstrlenA"], {})._strlen(pointer, unit)
        assert sum(size for _, size in memory.reads) == limit * unit, (unit, pointer)
        assert all((address & 0xFFF) + size <= 0x1000 for address, size in memory.reads)


def test_the_longest_string_the_stub_models_is_one_unit_short_of_the_bound():
    limit = emulate.MAX_STRLEN_UNITS
    book = emulate._StubBook(RecordingMemory(terminator_at=limit - 1), None, ["lstrlenA"], {})
    assert book._strlen(0x10001, 1)[0] == limit - 1
    memory = RecordingMemory(terminator_at=limit)
    with pytest.raises(emulate._StubStop, match="no terminator"):
        emulate._StubBook(memory, None, ["lstrlenA"], {})._strlen(0x10001, 1)
    wide = emulate._StubBook(RecordingMemory(terminator_at=(limit - 1) * 2), None, ["lstrlenW"], {})
    assert wide._strlen(0x10000, 2)[0] == limit - 1


# -- memory-access watch: off by default, address-range filtered, capped, never a way round the budgets -----------------------------

DATA = TEXT + 0x100
WATCH_ARGS = ("seq", "pc", "kind", "address", "size", "value")


def watched(sandbox, code, ranges, *, patches=(), **kwargs):
    """Run ``code`` with ``ranges`` watched and return the result; the sample is RWX so nothing faults by accident."""
    return emulate_json(build(sandbox, code, patches=patches), memory_watch=ranges, **kwargs)


def rng(start, end, access="both"):
    return {"start": start, "end": end, "access": access}


MIXED = (f"mov rax, {DATA}; mov rcx, 0x1122334455667788; mov qword ptr [rax], rcx; mov rdx, qword ptr [rax]; "
         f"mov byte ptr [rax + 0x40], 7; mov ebx, dword ptr [rax - 2]; ret")


def test_the_memory_watch_is_off_unless_ranges_are_given(sandbox):
    path = build(sandbox, asm(MIXED), patches=[(0x100 - 2, b"\xaa\xbb")])
    plain = emulate_json(path)
    assert plain["memory_trace"] is None and plain["memory_trace_truncated"] is False
    assert plain["memory_trace_skipped"] == 0 and plain["memory_trace_basis"] is None
    assert plain["request"]["memory_watch"] == [] and plain["limitations"] == []
    for empty in (None, []):
        assert emulate_json(path, memory_watch=empty)["memory_trace"] is None


def test_a_watch_does_not_change_what_the_run_does(sandbox):
    """The same program with a range that is never touched, with one that is, and with none: every other field of
    the result is the same, so the hook observes and does not steer."""
    path = build(sandbox, asm(MIXED), patches=[(0x100 - 2, b"\xaa\xbb")])
    keys = ("stop_reason", "stop_detail", "completion", "instructions", "rip", "registers", "recent_rips",
            "written_regions", "written_regions_total", "section_diffs")
    plain = emulate_json(path)
    for ranges in ([rng(0x200000, 0x200100)], [rng(DATA, DATA + 8)], [rng(DATA, DATA + 0x80, "write")]):
        traced = emulate_json(path, memory_watch=ranges)
        assert {k: traced[k] for k in keys if k != "section_diffs"} == {k: plain[k] for k in keys if k != "section_diffs"}
        assert [(r["name"], r["changed_bytes"], r["final_sha256"]) for r in traced["section_diffs"]] \
            == [(r["name"], r["changed_bytes"], r["final_sha256"]) for r in plain["section_diffs"]]
    assert emulate_json(path, memory_watch=[rng(0x200000, 0x200100)])["memory_trace"] == []


def test_reads_and_writes_in_a_range_are_recorded_with_pc_address_size_and_value(sandbox):
    result = watched(sandbox, asm(MIXED), [rng(DATA, DATA + 8)], patches=[(0x100 - 2, b"\xaa\xbb")])
    assert result["stop_reason"] == "RETURNED"
    trace = result["memory_trace"]
    assert [tuple(event) for event in trace] == [WATCH_ARGS] * len(trace)
    at = TEXT + len(asm(f"mov rax, {DATA}; mov rcx, 0x1122334455667788", TEXT))
    store = asm("mov qword ptr [rax], rcx", at)
    load = asm("mov rdx, qword ptr [rax]", at + len(store))
    assert trace[0] == {"seq": 1, "pc": hex(at), "kind": "write", "address": hex(DATA), "size": 8,
                        "value": "0x1122334455667788"}
    assert trace[1] == {"seq": 2, "pc": hex(at + len(store)), "kind": "read", "address": hex(DATA), "size": 8,
                        "value": "0x1122334455667788"}
    assert result["registers"]["rdx"] == "0x1122334455667788"
    # The dword at DATA-2 reaches into the range by two bytes: an overlap is recorded, with the bytes that were read.
    third = trace[2]
    assert (third["kind"], third["address"], third["size"], third["pc"]) == (
        "read", hex(DATA - 2), 4, hex(at + len(store) + len(load) + len(asm("mov byte ptr [rax + 0x40], 7", 0))))
    assert third["value"] == hex(int.from_bytes(b"\xaa\xbb" + b"\x88\x77", "little"))
    assert len(trace) == 3 and result["memory_trace_truncated"] is False and result["memory_trace_skipped"] == 0
    assert "attempt" in result["memory_trace_basis"] and result["request"]["memory_watch"] == [
        {"start": hex(DATA), "end": hex(DATA + 8), "access": "both"}]


def test_an_access_outside_the_range_is_not_recorded_and_the_range_is_half_open(sandbox):
    code = asm(f"mov rax, {DATA}; mov byte ptr [rax - 1], 1; mov byte ptr [rax + 8], 2; mov dword ptr [rax - 4], 3; "
               f"mov dword ptr [rax + 8], 4; mov byte ptr [rax + 7], 5; mov byte ptr [rax], 6; ret")
    result = watched(sandbox, code, [rng(DATA, DATA + 8)])
    assert [(e["address"], e["size"], e["value"]) for e in result["memory_trace"]] == [
        (hex(DATA + 7), 1, "0x5"), (hex(DATA), 1, "0x6")]


def test_the_access_kind_filters_reads_and_writes(sandbox):
    code = asm(f"mov rax, {DATA}; mov qword ptr [rax], rax; mov rbx, qword ptr [rax]; ret")
    for access, kinds in (("read", ["read"]), ("write", ["write"]), ("both", ["write", "read"])):
        result = watched(sandbox, code, [rng(DATA, DATA + 8, access)])
        assert [e["kind"] for e in result["memory_trace"]] == kinds, access
    default = watched(sandbox, code, [{"start": DATA, "end": DATA + 8}])        # access defaults to both
    assert [e["kind"] for e in default["memory_trace"]] == ["write", "read"]
    mixed = watched(sandbox, code, [rng(DATA - 0x10, DATA, "read"), rng(DATA, DATA + 8, "write")])
    assert [e["kind"] for e in mixed["memory_trace"]] == ["write"]


def test_several_ranges_are_watched_and_an_access_touching_two_is_recorded_once(sandbox):
    code = asm(f"mov rax, {DATA}; mov dword ptr [rax + 6], 0x01020304; mov byte ptr [rax + 0x20], 9; ret")
    result = watched(sandbox, code, [rng(DATA, DATA + 8, "write"), rng(DATA + 8, DATA + 16, "write"),
                                     rng(DATA + 0x20, DATA + 0x28, "write")])
    assert [(e["seq"], e["address"], e["size"]) for e in result["memory_trace"]] == [
        (1, hex(DATA + 6), 4), (2, hex(DATA + 0x20), 1)]


def test_a_read_that_cannot_be_read_is_listed_as_an_attempt_with_a_null_value(sandbox):
    code = asm("mov rbx, 0x10000000; mov rax, qword ptr [rbx]; ret")
    result = watched(sandbox, code, [rng(0x10000000, 0x10001000, "read")])
    assert result["stop_reason"] == "UNMAPPED_READ"
    assert [(e["kind"], e["address"], e["size"], e["value"]) for e in result["memory_trace"]] == [
        ("read", "0x10000000", 8, None)]


def test_the_trace_is_cut_at_the_cap_and_the_run_goes_on(sandbox):
    code = asm(f"mov rax, {DATA}; mov ecx, 20; l: mov byte ptr [rax], cl; dec ecx; jnz l; ret")
    full = watched(sandbox, code, [rng(DATA, DATA + 1)], memory_watch_limit=100)
    assert len(full["memory_trace"]) == 20 and full["memory_trace_truncated"] is False
    cut = watched(sandbox, code, [rng(DATA, DATA + 1)], memory_watch_limit=5)
    assert cut["stop_reason"] == "RETURNED" and cut["completion"] == "RETURNED"      # the cap does not stop emulation
    assert cut["memory_trace_truncated"] is True and cut["memory_trace_skipped"] == 15
    assert [e["seq"] for e in cut["memory_trace"]] == [1, 2, 3, 4, 5]
    assert cut["memory_trace"] == full["memory_trace"][:5]
    assert (cut["instructions"], cut["registers"]) == (full["instructions"], full["registers"])
    assert cut["request"]["memory_watch_limit"] == 5
    exact = watched(sandbox, code, [rng(DATA, DATA + 1)], memory_watch_limit=20)
    assert len(exact["memory_trace"]) == 20 and exact["memory_trace_truncated"] is False and exact["memory_trace_skipped"] == 0


def test_the_default_cap_is_a_thousand_and_the_ceiling_keeps_the_result_line_parseable(sandbox):
    assert emulate.DEFAULT_WATCH_EVENTS == 1000
    code = asm(f"mov rax, {DATA}; mov ecx, 1200; l: mov byte ptr [rax], cl; dec ecx; jnz l; ret")
    default = watched(sandbox, code, [rng(DATA, DATA + 1)])
    assert len(default["memory_trace"]) == 1000 and default["memory_trace_skipped"] == 200
    widest = {"seq": 10_000, "pc": "0x" + "f" * 16, "kind": "write", "address": "0x" + "f" * 16, "size": 16,
              "value": "0x" + "f" * 32}
    assert emulate.MAX_WATCH_EVENTS_CEILING * len(json.dumps(widest)) < emulate.MAX_CHILD_OUTPUT_CHARS // 2
    code = asm(f"mov rax, {DATA}; mov ecx, 10500; l: mov byte ptr [rax], cl; dec ecx; jnz l; ret")
    ceiling = watched(sandbox, code, [rng(DATA, DATA + 1)], memory_watch_limit=emulate.MAX_WATCH_EVENTS_CEILING)
    assert len(ceiling["memory_trace"]) == 10_000 and ceiling["memory_trace_skipped"] == 500
    assert ceiling["stop_reason"] == "RETURNED"


def test_the_watch_does_not_widen_the_instruction_or_time_budget(sandbox):
    code = asm(f"mov rax, {DATA}; l: mov byte ptr [rax], 1; jmp l")
    result = watched(sandbox, code, [rng(DATA, DATA + 1)], max_instructions=1001, memory_watch_limit=10)
    assert result["stop_reason"] == "INSN_LIMIT" and result["instructions"] == 1001
    assert len(result["memory_trace"]) == 10 and result["memory_trace_skipped"] == 500 - 10
    result = watched(sandbox, code, [rng(DATA, DATA + 1)], max_instructions=50_000_000, timeout_s=1)
    assert result["stop_reason"] == "TIMEOUT" and result["memory_trace_truncated"] is True
    assert len(result["memory_trace"]) == emulate.DEFAULT_WATCH_EVENTS


@pytest.mark.parametrize("ranges", [
    [rng(DATA, DATA)], [rng(DATA + 1, DATA)], [rng(-1, 8)], [rng(0, (1 << 64) + 1)], [rng("zz", 8)], [rng(True, 8)],
    [rng(DATA, DATA + 8, "execute")], [rng(DATA, DATA + 8, "rw")], [rng(DATA, DATA + 8, None)],
    [{"start": DATA}], [{"end": DATA}], [{"start": DATA, "end": DATA + 8, "extra": 1}], [(DATA, DATA + 8)], [5], "0x1:0x2",
    {"start": DATA, "end": DATA + 8},
    [rng(DATA, DATA + 8), rng(DATA + 4, DATA + 12)], [rng(DATA, DATA + 8, "read"), rng(DATA, DATA + 8, "write")],
    [rng(0, emulate.MAX_WATCH_SPAN + 1)], [rng(1 << 40, (1 << 40) + (1 << 32))],
    [rng(DATA + 16 * n, DATA + 16 * n + 8) for n in range(emulate.MAX_WATCH_RANGES + 1)],
])
def test_an_invalid_range_is_refused_before_anything_runs(sandbox, ranges):
    result = emulate_json(build(sandbox, asm("ret")), memory_watch=ranges)
    assert result["status"] == "TOOL_USAGE" and result["error"] == "BAD_MEMORY_WATCH" and result["ok"] is False
    assert result.get("operation_ran") is not True and result.get("stop_reason") is None


@pytest.mark.parametrize("limit", [0, -1, emulate.MAX_WATCH_EVENTS_CEILING + 1, True, 5.0, "10", None])
def test_a_cap_outside_its_bounds_is_refused(sandbox, limit):
    result = emulate_json(build(sandbox, asm("ret")), memory_watch=[rng(DATA, DATA + 8)], memory_watch_limit=limit)
    assert result["status"] == "TOOL_USAGE" and result["error"] == "BAD_MEMORY_WATCH"


def test_the_largest_range_and_the_most_ranges_are_accepted(sandbox):
    path = build(sandbox, asm("ret"))
    largest = emulate_json(path, memory_watch=[rng(0, emulate.MAX_WATCH_SPAN)])
    assert largest["stop_reason"] == "RETURNED" and largest["memory_trace"] == []
    many = emulate_json(path, memory_watch=[rng(DATA + 16 * n, DATA + 16 * n + 8) for n in range(emulate.MAX_WATCH_RANGES)])
    assert many["stop_reason"] == "RETURNED" and many["memory_trace"] == []
    top = emulate_json(path, memory_watch=[rng((1 << 64) - 8, 1 << 64)])
    assert top["stop_reason"] == "RETURNED"


def test_stub_memory_effects_are_not_in_the_trace_but_the_codes_own_accesses_are(sandbox):
    patches = [(STRING_AT, b"hello\0")]
    path = program(sandbox, ("data", "rcx", STRING_AT), "@lstrlenA", "mov rdx, qword ptr [rcx]",
                   "mov qword ptr [rcx + 8], rdx", "ret", patches=patches)
    result = emulate_json(path, allow_stubs=["lstrlenA"], memory_watch=[rng(TEXT + STRING_AT, TEXT + STRING_AT + 0x10)])
    assert result["stop_reason"] == "RETURNED"
    assert result["stubs"]["calls"][0]["effects"] == [{"kind": "read", "va": hex(TEXT + STRING_AT), "bytes": 5}]
    assert [(e["seq"], e["kind"], e["address"]) for e in result["memory_trace"]] == [
        (1, "read", hex(TEXT + STRING_AT)), (2, "write", hex(TEXT + STRING_AT + 8))]
    assert "stubs.calls" in result["memory_trace_basis"]


def test_vex_memory_operands_are_not_hooked_and_the_result_says_the_trace_may_be_incomplete(sandbox):
    code = Code().vmovdqu_load(0, 0x100).vmovdqu_store(OUT_BLOCK, 0).asm("ret")
    path = build(sandbox, bytes(code.blob), patches=[(0x100, A_BLOCK)])
    traced = emulate_json(path, memory_watch=[rng(TEXT + 0x100, TEXT + 0x130)])
    assert traced["vex"]["instructions_executed_by_layer"] == 2
    assert [item["code"] for item in traced["limitations"]] == ["MEMORY_TRACE_INCOMPLETE"]
    assert traced["memory_trace"] == []                  # the gap the limitation names, pinned rather than hidden
    assert emulate_json(path)["limitations"] == []


def test_the_emulate_subcommand_takes_repeatable_mem_watch_flags(sandbox, capsys):
    path = build(sandbox, asm(f"mov rax, {DATA}; mov qword ptr [rax], rax; mov rbx, qword ptr [rax + 0x10]; ret"))
    base = ["emulate", _relative(path), "--start", hex(TEXT), "--target-class", "public_crackme"]
    code, out = run_cli(capsys, *base, "--mem-watch", f"{hex(DATA)}:{hex(DATA + 8)}:w",
                        "--mem-watch", f"{DATA + 0x10}:{DATA + 0x18}")
    assert code == 0 and [(e["kind"], e["address"]) for e in out["memory_trace"]] == [
        ("write", hex(DATA)), ("read", hex(DATA + 0x10))]
    assert out["request"]["memory_watch"][0] == {"start": hex(DATA), "end": hex(DATA + 8), "access": "write"}
    code, out = run_cli(capsys, *base, "--mem-watch", f"{hex(DATA)}:{hex(DATA + 8)}:r", "--mem-watch-limit", "1")
    assert code == 0 and out["memory_trace"] == [] and out["memory_trace_truncated"] is False
    code, out = run_cli(capsys, *base)
    assert code == 0 and out["memory_trace"] is None
    code, out = run_cli(capsys, *base, "--mem-watch", f"{hex(DATA + 8)}:{hex(DATA)}")
    assert code != 0 and out["error"] == "BAD_MEMORY_WATCH"
    for bad in ("0x10", "a:b", "1:2:x", "1:2:rw:3"):
        with pytest.raises(SystemExit):
            cli.main([*base, "--mem-watch", bad])
        capsys.readouterr()


def test_an_access_that_faults_is_listed_once_as_the_last_event(sandbox):
    protected = emulate_json(build(sandbox, asm(f"mov rax, {DATA}; mov dword ptr [rax], 0x01020304; ret"), chars=RX),
                             memory_watch=[rng(DATA, DATA + 8)])
    assert protected["stop_reason"] == "WRITE_PROTECT"
    assert [(e["kind"], e["address"], e["size"], e["value"]) for e in protected["memory_trace"]] == [
        ("write", hex(DATA), 4, "0x1020304")]
    unmapped = watched(sandbox, asm("mov rbx, 0x10000000; mov qword ptr [rbx + 8], rbx; ret"),
                       [rng(0x10000000, 0x10001000, "write")])
    assert unmapped["stop_reason"] == "UNMAPPED_WRITE"
    assert [(e["kind"], e["address"], e["size"], e["value"]) for e in unmapped["memory_trace"]] == [
        ("write", "0x10000008", 8, "0x10000000")]
    unfiltered = watched(sandbox, asm("mov rbx, 0x10000000; mov rax, qword ptr [rbx]; ret"),
                         [rng(0x10000000, 0x10001000, "write")])
    assert unfiltered["stop_reason"] == "UNMAPPED_READ" and unfiltered["memory_trace"] == []


def test_a_mem_watch_address_is_hex_with_0x_and_decimal_otherwise(sandbox):
    """A leading zero is not octal and not an error: ``010`` is ten. The rule is 0x means base 16, else base 10."""
    assert cli._mem_watch("010:020") == {"start": 10, "end": 20, "access": "both"}
    assert cli._mem_watch("0x10:0X20:w") == {"start": 16, "end": 32, "access": "write"}
    assert cli._mem_watch("00:0x0A:r") == {"start": 0, "end": 10, "access": "read"}
    for bad in ("0x:1", "-1:5", "1_0:20", "0b11:20", "0o7:9", " :5", "1.5:9", "0xZZ:5"):
        with pytest.raises(argparse.ArgumentTypeError):
            cli._mem_watch(bad)


def test_wide_accesses_arrive_in_pieces_of_at_most_8_bytes_each_with_a_value_and_the_basis_says_what_was_measured(sandbox):
    """A 16-byte SSE access and an 80-bit x87 store reach the hook as pieces the engine splits, each with its value;
    the basis names the limits (16 bytes read, 8 written) and that nothing wider was ever delivered."""
    code = asm(f"mov rax, {DATA}; movups xmm0, xmmword ptr [rax + 0x20]; movups xmmword ptr [rax], xmm0; "
               "fld1; fstp tbyte ptr [rax + 0x10]; ret")
    result = watched(sandbox, code, [rng(DATA, DATA + 0x30)], patches=[(0x100 + 0x20, bytes(range(1, 17)))])
    assert result["stop_reason"] == "RETURNED"
    assert [(e["kind"], e["size"]) for e in result["memory_trace"]] == [
        ("read", 8), ("read", 8), ("write", 8), ("write", 8), ("write", 8), ("write", 2)]
    assert all(e["value"] is not None for e in result["memory_trace"])
    assert result["memory_trace"][0]["value"] == hex(int.from_bytes(bytes(range(1, 9)), "little"))
    basis = result["memory_trace_basis"]
    assert "read of at most 16 bytes" in basis and "write of at most 8 bytes" in basis
    assert "nothing wider than 8 bytes" in basis and "was not observed" in basis


# -- input injection and variant runs -------------------------------------------------------------------------------

STACK_HIGH = 0x7FFC0000
INITIAL_RSP = STACK_HIGH - 0x100 + 8
CHECK_BODY = "movzx eax, byte ptr [rcx]; cmp al, 0x42; jne bad; mov rax, 0x1111; ret; bad: mov rax, 0x2222; ret"
SECRET_HEX = "c0ffee11deadbeef"       # distinctive bytes: they must never appear in a result or a record


def check_image(sandbox, **kwargs):
    """A routine that reads the first byte of the buffer RCX points at and returns 0x1111 for 0x42, else 0x2222."""
    return build(sandbox, asm(CHECK_BODY), **kwargs)


def variants_of(result):
    return {row["input"]["sha256"]: row for row in result["variants"]}


def test_two_inputs_give_two_different_outcomes_in_one_request(sandbox):
    path = check_image(sandbox)
    result = emulate_json(path, input_variants=["42", "41"], input_at="reg:RCX")
    assert result["ok"] is True and result["status"] == "OK" and result["variant_mode"] is True
    first, second = result["variants"]
    assert (first["stop_reason"], first["completion"], first["registers"]["rax"]) == ("RETURNED", "RETURNED", "0x1111")
    assert (second["stop_reason"], second["completion"], second["registers"]["rax"]) == ("RETURNED", "RETURNED", "0x2222")
    assert first["registers"]["rcx"] == hex(emulate.INPUT_VA) == second["registers"]["rcx"]
    assert first["input"]["sha256"] == hashlib.sha256(b"\x42").hexdigest() and first["input"]["length"] == 1
    assert second["input"]["sha256"] == hashlib.sha256(b"\x41").hexdigest()
    assert (result["variants_total"], result["variants_run"], result["variants_not_run"]) == (2, 2, 0)
    assert result["total_budget_exhausted"] is False and "fresh emulator" in result["variants_basis"]
    assert [r["index"] for r in result["variants"]] == [0, 1] and result["completion"] is None
    # the same input as a single run gives the same registers and instruction count as its variant
    single = emulate_json(path, input_data="42", input_at="reg:rcx")
    assert single["registers"] == first["registers"] and single["instructions"] == first["instructions"]
    assert single["input_injection"]["sha256"] == first["input"]["sha256"]


@pytest.mark.parametrize("register", ["rcx", "rdx", "r8", "r9", "rsi", "r15"])
def test_the_buffer_address_goes_into_the_named_register_and_the_buffer_is_there(sandbox, register):
    code = asm(f"mov rax, qword ptr [{register}]; mov rbx, {register}; ret")
    result = emulate_json(build(sandbox, code), input_data="0102030405060708", input_at=f"reg:{register.upper()}")
    assert result["stop_reason"] == "RETURNED"
    assert result["registers"]["rax"] == hex(int.from_bytes(bytes(range(1, 9)), "little"))
    assert result["registers"]["rbx"] == hex(emulate.INPUT_VA) == result["registers"][register]
    injected = result["input_injection"]
    assert (injected["mode"], injected["register"], injected["length"], injected["region_bytes"]) == (
        "register", register, 8, 0x1000)
    assert injected["buffer_address"] == hex(emulate.INPUT_VA) and injected["content_omitted"] is True
    assert result["input_basis"] and "never its content" in result["input_basis"]


def test_a_buffer_can_be_written_to_a_mapped_address_instead(sandbox):
    code = asm(f"mov rcx, {DATA}; {CHECK_BODY}")
    path = build(sandbox, code)
    for data, rax in (("42", "0x1111"), ("43", "0x2222")):
        result = emulate_json(path, input_data=data, input_at=hex(DATA))
        assert result["stop_reason"] == "RETURNED" and result["registers"]["rax"] == rax
        assert result["input_injection"]["mode"] == "address" and result["input_injection"]["region_bytes"] is None
        assert result["input_injection"]["buffer_address"] == hex(DATA)
        # bytes injected into the image are a difference from the loaded image, and the result says so
        assert result["section_diffs"][0]["changed_bytes"] == 1
    stack = emulate_json(path, input_data="42", input_at=INITIAL_RSP - 0x80)      # the stack is writable memory too
    assert stack["stop_reason"] == "RETURNED" and stack["input_injection"]["buffer_address"] == hex(INITIAL_RSP - 0x80)
    assert stack["registers"]["rax"] == "0x2222"         # the routine reads DATA, which holds 0, not the stack buffer


def test_the_result_and_the_record_carry_the_hash_and_length_of_the_input_and_never_its_content(sandbox):
    path = check_image(sandbox)
    for kwargs in ({"input_data": SECRET_HEX}, {"input_variants": [SECRET_HEX, "01"]}):
        result = emulate_json(path, input_at="reg:rcx", **kwargs)
        text = json.dumps(result)
        assert SECRET_HEX not in text and "c0ffee11" not in text and "deadbeef" not in text
        record = (emulate.EVIDENCE / result["evidence_name"]).read_text(encoding="utf-8")
        assert SECRET_HEX not in record and "deadbeef" not in record
        buffers = result["request"]["input"]["buffers"]
        assert buffers[0] == {"sha256": hashlib.sha256(bytes.fromhex(SECRET_HEX)).hexdigest(), "length": 8}
        assert result["request"]["input"]["content_omitted"] is True
        assert result["request"]["input"]["mode"] == "register"
    # with no input there is no injection and the field says so
    plain = emulate_json(path, registers={"rcx": 0})
    assert plain["input_injection"] is None and plain["request"]["input"] is None and "variant_mode" not in plain


LEAKY = (f"mov rdx, {DATA}; mov rbx, qword ptr [rdx]; mov rdi, qword ptr [rsp - 0x40]; movzx eax, byte ptr [rcx]; "
         "test eax, eax; jz out; mov dword ptr [rdx], 0x5A5A5A5A; mov qword ptr [rsp - 0x40], 0x77; "
         "mov r12, 0x99; stc; out: mov rax, r12; ret")


def test_a_variant_never_sees_what_an_earlier_one_wrote(sandbox):
    """Variant 0 and 2 (input 1) write a marker to .text, to the stack, set r12 and the carry flag; variant 1
    (input 0) reads all four and must find the initial state. Variant 2 repeats variant 0 exactly."""
    path = build(sandbox, asm(LEAKY))
    result = emulate_json(path, input_variants=["01", "00", "01", "00"], input_at="reg:rcx")
    one, zero, one_again, zero_again = result["variants"]
    assert one["registers"]["rax"] == "0x99" and one["registers"]["rbx"] == "0x0"
    assert [r["size"] for r in one["written_regions"]] == [4]       # the stack write is outside the image: not listed
    assert one["sections_changed"] and one["dump_files"]
    # nothing leaked into the variant that ran after a writer
    for clean in (zero, zero_again):
        assert clean["stop_reason"] == "RETURNED"
        assert clean["registers"]["rbx"] == "0x0", "memory written by an earlier variant is visible"
        assert clean["registers"]["rdi"] == "0x0", "the stack of an earlier variant is visible"
        assert clean["registers"]["rax"] == "0x0" and clean["registers"]["r12"] == "0x0", "a register leaked"
        assert int(clean["registers"]["eflags"], 16) & 1 == 0, "the carry flag leaked"
        assert clean["written_regions"] == [] and clean["sections_changed"] == [] and clean["dump_files"] == []
    keys = ("stop_reason", "stop_detail", "completion", "instructions", "registers", "written_regions", "rip")
    assert {k: one_again[k] for k in keys} == {k: one[k] for k in keys}
    assert {k: zero_again[k] for k in keys} == {k: zero[k] for k in keys}
    # the dumps are per variant: the second writer has its own file, with its own marker
    assert one["dump_files"] != one_again["dump_files"]
    first = dump_bytes(result, one["dump_files"][0])
    second = dump_bytes(result, one_again["dump_files"][0])
    assert first == second and first[0x100:0x104] == bytes.fromhex("5a5a5a5a")


def test_stub_state_does_not_carry_between_variants(sandbox):
    """The allocator a variant used is fresh for the next: both get the first block, and what the first wrote into
    it is not there for the second. r9 carries the input pointer, which HeapAlloc (three arguments) leaves alone."""
    path = program(sandbox, "mov ecx, 0", "mov edx, 0", "mov r8d, 0x20", "@HeapAlloc", "mov rbx, rax",
                   "movzx edi, byte ptr [rbx]", "mov byte ptr [rbx], 0x55", "ret")
    result = emulate_json(path, input_variants=["01", "02"], input_at="reg:r9", allow_stubs=["HeapAlloc"],
                          stub_options={"heap_bytes": 0x2000})
    for row in result["variants"]:
        assert row["stop_reason"] == "RETURNED", row["stop_detail"]
        assert row["registers"]["rbx"] == hex(emulate.STUB_HEAP_VA) and row["registers"]["rdi"] == "0x0"
        assert row["stubs"]["calls_total"] == 1 and row["stubs"]["heap"]["used"] == 0x20
        assert row["registers"]["r9"] == hex(emulate.INPUT_VA)
    assert [e["code"] for e in result["limitations"]] == ["STUBBED_IMPORTS"]


def test_the_instruction_bound_applies_to_each_variant_not_to_the_request(sandbox):
    loop = asm("movzx ecx, byte ptr [rcx]; test ecx, ecx; jz done; l: dec ecx; jnz l; done: mov eax, 7; ret")
    path = build(sandbox, loop)
    result = emulate_json(path, input_variants=["64", "64", "c8"], input_at="reg:rcx", max_instructions=250)
    first, second, third = result["variants"]
    assert (first["stop_reason"], second["stop_reason"]) == ("RETURNED", "RETURNED")
    assert first["instructions"] == second["instructions"] == 3 + 2 * 100 + 2 and first["instructions"] < 250
    assert 2 * first["instructions"] > 250            # together they exceed the bound that each stays under
    assert (third["stop_reason"], third["instructions"], third["completion"]) == ("INSN_LIMIT", 250, "INSN_LIMIT")
    assert result["bounds"]["max_instructions"] == 250


SPIN = asm("cmp byte ptr [rcx], 0; jne spin; ret; spin: jmp spin")


def slow_preparation(monkeypatch, skews):
    """A controllable clock for the variant runner, and a parse step that moves it. ``skews`` maps the 0-based
    preparation (one per variant) to the seconds that preparation appears to take."""
    skew, real, calls = [0.0], time.monotonic, [0]
    original = emulate._Engine.parse_pe

    def slow_parse(data):
        skew[0] += skews.get(calls[0], 0.0)
        calls[0] += 1
        return original(data)

    monkeypatch.setattr(time, "monotonic", lambda: real() + skew[0])
    monkeypatch.setattr(emulate._Engine, "parse_pe", staticmethod(slow_parse))
    return skew


def test_a_variant_whose_preparation_outlasts_the_total_budget_is_not_run(sandbox, monkeypatch):
    """Variant 1 is started with budget left, then its parse and map take longer than the whole total. The run
    check at the top of the loop is stale by then: the variant must be reported as not run, not run in full."""
    path = build(sandbox, SPIN)
    slow_preparation(monkeypatch, {1: 1e6})
    result = run_in_process(path, input_variants=["00", "01", "00"], input_at="reg:rcx", max_instructions=5000,
                            timeout_s=100, total_timeout_s=50)
    first, second, third = result["variants"]
    assert first["ran"] is True and first["stop_reason"] == "RETURNED"
    for row in (second, third):
        assert row["ran"] is False and row["not_run_because"] == "TOTAL_TIME_BUDGET_EXHAUSTED"
        assert row["stop_reason"] is None and row["completion"] is None and "registers" not in row
    assert second["input"]["sha256"] == hashlib.sha256(b"").hexdigest()
    assert result["variants_run"] == 1 and result["variants_not_run"] == 2 and result["total_budget_exhausted"] is True


def test_a_variant_deadline_never_passes_the_total_deadline(sandbox, monkeypatch):
    """Preparation takes 40 s of a 50 s total with 100 s per variant: what is left after it, not what was left
    before it, bounds the variant."""
    path = build(sandbox, SPIN)
    slow_preparation(monkeypatch, {0: 40.0})
    result = run_in_process(path, input_variants=["01"], input_at="reg:rcx", max_instructions=5000,
                            timeout_s=100, total_timeout_s=50)
    row = result["variants"][0]
    assert row["ran"] is True and row["budget_limited_by_total"] is True
    assert 0 < row["budget_s"] <= 10.0 + 1e-6, row["budget_s"]


def test_the_time_bound_applies_to_each_variant_and_the_total_bound_to_all_of_them(sandbox, monkeypatch):
    """The same behaviour as the wall-clock test below, on a clock the test moves: every instruction-hook check
    sees time pass, so no machine load can change which variants run."""
    path = build(sandbox, SPIN)
    real, ticks = time.monotonic, [0.0]

    def clock():
        ticks[0] += 0.001
        return real() * 0 + ticks[0]

    monkeypatch.setattr(time, "monotonic", clock)
    result = run_in_process(path, input_variants=["01", "01", "01"], input_at="reg:rcx", max_instructions=50_000_000,
                            timeout_s=1, total_timeout_s=1.5)
    rows = result["variants"]
    assert rows[0]["stop_reason"] == "TIMEOUT" and rows[0]["completion"] == "TIMEOUT"
    assert rows[0]["budget_s"] == 1.0 and rows[0]["budget_limited_by_total"] is False
    assert rows[1]["ran"] is True and rows[1]["stop_reason"] == "TIMEOUT" and rows[1]["budget_limited_by_total"] is True
    assert rows[1]["budget_s"] < 0.5
    assert rows[-1]["ran"] is False and rows[-1]["not_run_because"] == "TOTAL_TIME_BUDGET_EXHAUSTED"
    assert rows[-1]["stop_reason"] is None and rows[-1]["completion"] is None
    assert rows[-1]["input"]["sha256"] == hashlib.sha256(b"").hexdigest()
    assert result["total_budget_exhausted"] is True and result["variants_not_run"] == 1
    assert result["variants_run"] + result["variants_not_run"] == 3 == result["variants_total"]
    assert result["total_budget_s"] == 1.5


def test_the_time_bounds_hold_on_the_real_clock_with_wide_margins(sandbox):
    """Only what a wall clock can show: the request returns, a timed-out variant is a TIMEOUT, and the total
    stops the later ones. No exact budget or count is asserted, so a loaded machine cannot fail it."""
    path = build(sandbox, SPIN)
    started = time.monotonic()
    result = emulate_json(path, input_variants=["01", "01", "01"], input_at="reg:rcx", max_instructions=50_000_000,
                          timeout_s=1, total_timeout_s=1.5)
    elapsed = time.monotonic() - started
    rows = result["variants"]
    assert rows[0]["stop_reason"] == "TIMEOUT"
    assert result["variants_run"] + result["variants_not_run"] == 3 and result["total_budget_exhausted"] is True
    assert all(r["not_run_because"] == "TOTAL_TIME_BUDGET_EXHAUSTED" for r in rows if not r["ran"])
    assert result["total_budget_s"] == 1.5 and elapsed < 60


def test_the_default_total_time_bound_is_the_variant_bound_times_the_count_capped(sandbox):
    # the default total is the per-variant bound times the count, capped at the ceiling
    quick = emulate_json(check_image(sandbox), input_variants=["42", "42"], input_at="reg:rcx", timeout_s=7)
    assert quick["total_budget_s"] == 14.0 and quick["bounds"]["total_timeout_s"] == 14.0
    assert emulate_json(check_image(sandbox), input_variants=["42"] * 3, input_at="reg:rcx",
                        timeout_s=400)["total_budget_s"] == 600.0


def test_each_variant_has_its_own_memory_trace(sandbox):
    code = asm(f"mov rdx, {DATA}; movzx eax, byte ptr [rcx]; mov byte ptr [rdx + rax], 1; ret")
    path = build(sandbox, code)
    result = emulate_json(path, input_variants=["00", "03"], input_at="reg:rcx", memory_watch=[rng(DATA, DATA + 8)],
                          memory_watch_limit=10)
    first, second = result["variants"]
    assert [(e["seq"], e["kind"], e["address"]) for e in first["memory_trace"]] == [(1, "write", hex(DATA))]
    assert [(e["seq"], e["kind"], e["address"]) for e in second["memory_trace"]] == [(1, "write", hex(DATA + 3))]
    assert first["memory_trace_truncated"] is False and result["memory_trace_basis"]
    plain = emulate_json(path, input_variants=["00"], input_at="reg:rcx")
    assert plain["variants"][0]["memory_trace"] is None


def test_the_buffer_counts_as_emulated_memory_and_the_largest_one_is_accepted(sandbox):
    path = check_image(sandbox)
    small = emulate_json(path, input_data="42", input_at="reg:rcx")
    largest = emulate_json(path, input_data=bytes([0x42]) * emulate.MAX_INPUT_BYTES, input_at="reg:rcx")
    assert largest["stop_reason"] == "RETURNED" and largest["input_injection"]["region_bytes"] == 0x10000
    assert largest["mapped_bytes"] - small["mapped_bytes"] == 0x10000 - 0x1000
    assert largest["input_injection"]["length"] == 0x10000
    thirty_two = emulate_json(path, input_variants=["42"] * emulate.MAX_VARIANTS, input_at="reg:rcx")
    assert thirty_two["variants_run"] == 32 and {r["registers"]["rax"] for r in thirty_two["variants"]} == {"0x1111"}
    assert all(r["mapped_bytes"] == small["mapped_bytes"] for r in thirty_two["variants"])


@pytest.mark.parametrize("kwargs, error", [
    ({"input_data": "42"}, "BAD_INPUT"),                                                          # no input_at
    ({"input_data": "42", "input_variants": ["42"], "input_at": "reg:rcx"}, "BAD_INPUT"),         # both forms
    ({"input_at": "reg:rcx"}, "BAD_INPUT"),                                                       # no buffer
    ({"total_timeout_s": 5}, "BAD_INPUT"),
    ({"input_data": "", "input_at": "reg:rcx"}, "BAD_INPUT"),                                     # empty
    ({"input_data": b"", "input_at": "reg:rcx"}, "BAD_INPUT"),
    ({"input_data": "4", "input_at": "reg:rcx"}, "BAD_INPUT"),                                    # odd length
    ({"input_data": "zz", "input_at": "reg:rcx"}, "BAD_INPUT"),
    ({"input_data": "0x42", "input_at": "reg:rcx"}, "BAD_INPUT"),
    ({"input_data": 42, "input_at": "reg:rcx"}, "BAD_INPUT"),
    ({"input_data": b"\x00" * (emulate.MAX_INPUT_BYTES + 1), "input_at": "reg:rcx"}, "BAD_INPUT"),
    ({"input_variants": [], "input_at": "reg:rcx"}, "BAD_INPUT"),
    ({"input_variants": "42", "input_at": "reg:rcx"}, "BAD_INPUT"),
    ({"input_variants": ["42"] * (emulate.MAX_VARIANTS + 1), "input_at": "reg:rcx"}, "BAD_INPUT"),
    ({"input_variants": ["42", "zz"], "input_at": "reg:rcx"}, "BAD_INPUT"),
    ({"input_variants": [b"\x00" * emulate.MAX_INPUT_BYTES] * 17, "input_at": "reg:rcx"}, "BAD_INPUT"),   # over 1 MiB together
    ({"input_data": "42", "input_at": "reg:rsp"}, "BAD_INPUT"),
    ({"input_data": "42", "input_at": "reg:rip"}, "BAD_INPUT"),
    ({"input_data": "42", "input_at": "reg:"}, "BAD_INPUT"),
    ({"input_data": "42", "input_at": "rcx"}, "BAD_INPUT"),
    ({"input_data": "42", "input_at": "-1"}, "BAD_INPUT"),
    ({"input_data": "42", "input_at": True}, "BAD_INPUT"),
    ({"input_data": "42", "input_at": hex(1 << 64)}, "BAD_INPUT"),
    ({"input_data": "42424242", "input_at": hex((1 << 64) - 2)}, "BAD_INPUT"),                   # runs past 2**64
    ({"input_data": "42", "input_at": "reg:rcx", "registers": {"rcx": 5}}, "BAD_INPUT"),        # contradicting registers
    ({"input_data": "42", "input_at": "reg:rcx", "total_timeout_s": 5}, "BAD_INPUT"),           # single run
    ({"input_variants": ["42"], "input_at": "reg:rcx", "total_timeout_s": 0}, "BAD_TIMEOUT"),
    ({"input_variants": ["42"], "input_at": "reg:rcx", "total_timeout_s": 601}, "BAD_TIMEOUT"),
    ({"input_variants": ["42"], "input_at": "reg:rcx", "total_timeout_s": True}, "BAD_TIMEOUT"),
    ({"input_variants": ["42", "42"], "input_at": "reg:rcx", "memory_watch": [{"start": 0, "end": 8}],
      "memory_watch_limit": 5001}, "BAD_MEMORY_WATCH"),                                          # one bounded result line
])
def test_an_invalid_input_request_is_refused_before_anything_runs(sandbox, kwargs, error):
    result = emulate_json(check_image(sandbox), **kwargs)
    assert result["ok"] is False and result["status"] == "TOOL_USAGE" and result["error"] == error
    assert result["completion"] is None and "operation_ran" not in result and "run_id" not in result


def test_a_watch_limit_that_fits_the_variant_count_is_accepted(sandbox):
    result = emulate_json(check_image(sandbox), input_variants=["42", "42"], input_at="reg:rcx",
                          memory_watch=[rng(DATA, DATA + 8)], memory_watch_limit=5000)
    assert result["ok"] is True and result["variants_run"] == 2


@pytest.mark.parametrize("address, detail", [
    (0x1234, "mapped, writable"),                                  # unmapped
    (IMAGE_BASE, "mapped, writable"),                              # the read-only headers
    (INITIAL_RSP - 3, "return slot"),                              # a buffer that reaches the sentinel slot
    (INITIAL_RSP, "return slot"),
    (0x7FFDA000, "TEB"),
    (0x7FFDE000 + 0xFFE, "PEB"),
    (SENTINEL, "return sentinel"),
    (STACK_HIGH - 2, "mapped, writable"),                          # runs off the top of the stack
])
def test_an_address_the_buffer_cannot_be_written_to_is_refused_and_nothing_runs(sandbox, address, detail):
    result = emulate_json(check_image(sandbox), input_data="42424242", input_at=address)
    assert result["status"] == "TOOL_USAGE" and result["error"] == "BAD_INPUT_ADDRESS" and detail in result["detail"]
    assert result["stop_reason"] is None and result["completion"] is None
    variants = emulate_json(check_image(sandbox), input_variants=["42", "42424242"], input_at=address)
    assert variants["error"] == "BAD_INPUT_ADDRESS" and "variants" not in variants


def test_an_address_in_a_section_declared_read_only_is_refused_unless_rwx_is_forced(sandbox):
    path = build(sandbox, asm(f"mov rcx, {DATA}; {CHECK_BODY}"), chars=RX)
    refused = emulate_json(path, input_data="42", input_at=hex(DATA))
    assert refused["error"] == "BAD_INPUT_ADDRESS" and "writable" in refused["detail"]
    forced = emulate_json(path, input_data="42", input_at=hex(DATA), perm_mode="rwx")
    assert forced["registers"]["rax"] == "0x1111" and forced["input_injection"]["buffer_address"] == hex(DATA)


def test_a_refusal_in_a_later_variant_names_the_variant_and_fails_the_request(sandbox):
    """Address mode: the first buffer fits below the end of the stack, the second does not."""
    result = emulate_json(check_image(sandbox), input_variants=["42", "4242424242424242"], input_at=STACK_HIGH - 4)
    assert result["status"] == "TOOL_USAGE" and result["error"] == "BAD_INPUT_ADDRESS"
    assert result["detail"].startswith("variant 1:") and "variants" not in result


def test_a_numeric_string_with_a_leading_zero_is_decimal_not_an_error():
    assert emulate._int_value("010") == 10 and emulate._int_value("0x10") == 16 and emulate._int_value(" 07 ") == 7
    assert emulate._int_value("0b1") is None and emulate._int_value("1_0") is None and emulate._int_value("-1") is None
    assert emulate._int_value(True) is None and emulate._int_value(5) == 5


def test_the_emulate_subcommand_injects_one_input_and_runs_variants(sandbox, capsys):
    path = check_image(sandbox)
    base = ["emulate", _relative(path), "--start", hex(TEXT), "--target-class", "public_crackme"]
    code, out = run_cli(capsys, *base, "--input-hex", "42", "--input-at", "reg:RCX")
    assert code == 0 and out["registers"]["rax"] == "0x1111" and out["input_injection"]["register"] == "rcx"
    blob = sandbox / "buffer.bin"
    blob.write_bytes(b"\x41")
    code, out = run_cli(capsys, *base, "--input-file", _relative(blob), "--input-at", "reg:rcx")
    assert code == 0 and out["registers"]["rax"] == "0x2222" and out["registers"]["rcx"] == hex(emulate.INPUT_VA) \
        and out["input_injection"]["sha256"] == hashlib.sha256(b"\x41").hexdigest()
    lines = sandbox / "variants.txt"
    lines.write_text("42\n 41 \nc0ffee\n", encoding="ascii")
    code, out = run_cli(capsys, *base, "--variants-file", _relative(lines), "--input-at", "reg:RCX", "--total-timeout", "30")
    assert code == 0 and [r["registers"]["rax"] for r in out["variants"]] == ["0x1111", "0x2222", "0x2222"]
    assert out["total_budget_s"] == 30.0 and out["command"] == "emulate"
    assert "c0ffee" not in json.dumps(out)
    # the same through an address
    code, out = run_cli(capsys, *base, "--reg", "rcx=" + hex(DATA), "--input-hex", "42", "--input-at", hex(DATA))
    assert code == 0 and out["registers"]["rax"] == "0x1111" and out["input_injection"]["mode"] == "address"
    code, out = run_cli(capsys, *base, "--input-hex", "42", "--input-at", "reg:rcx", "--reg", "rcx=1")
    assert code != 0 and out["error"] == "BAD_INPUT"


def test_the_emulate_subcommand_refuses_unusable_input_flags(sandbox, capsys):
    path = check_image(sandbox)
    base = ["emulate", _relative(path), "--start", hex(TEXT), "--target-class", "public_crackme"]
    blank = sandbox / "blank.txt"
    blank.write_text("42\n\n41\n", encoding="ascii")
    nonascii = sandbox / "nonascii.txt"
    nonascii.write_bytes("42\n\u00e9\n".encode("utf-8"))
    big = sandbox / "big.bin"
    big.write_bytes(b"\x00" * (emulate.MAX_INPUT_BYTES + 1))
    for argv in (["--input-hex", "42"],                                                       # no --input-at
                 ["--input-at", "reg:rcx"],                                                   # no input
                 ["--total-timeout", "5"],
                 ["--input-hex", "42", "--input-file", _relative(big), "--input-at", "reg:rcx"],
                 ["--input-hex", "42", "--variants-file", _relative(blank), "--input-at", "reg:rcx"],
                 ["--variants-file", _relative(blank), "--input-at", "reg:rcx"],              # blank line
                 ["--variants-file", _relative(nonascii), "--input-at", "reg:rcx"],
                 ["--input-file", _relative(big), "--input-at", "reg:rcx"],                    # over the size bound
                 ["--input-file", _relative(sandbox / "missing.bin"), "--input-at", "reg:rcx"],
                 ["--input-hex", "4", "--input-at", "reg:rcx"],                               # odd hex
                 ["--input-hex", "42", "--input-at", "reg:rsp"]):
        code, out = run_cli(capsys, *base, *argv)
        assert code != 0 and out["ok"] is False and out["status"] in ("TOOL_USAGE", "PATH_REFUSED"), argv
        assert out.get("stop_reason") is None
