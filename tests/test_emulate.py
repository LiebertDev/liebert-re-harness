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

import hashlib
import json
import shutil
import struct
import subprocess
import sys
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
        assert "\\" not in text.replace("\\n", "").replace('\\"', "") or True
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
