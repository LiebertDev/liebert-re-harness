"""Deterministic ground-truth verifier for ``constant_at_address`` claims.

GAP-061 step 1-2 (see docs/PROJECT_STATE.md): a finding whose claim is "this
constant value is used in a comparison at this instruction address" (the
exact shape of the harness's own proven ``ioctl_code_recovery`` capability --
see ``tests/test_ioctl_recovery.py``, which recovered
``IOCTL_KBFILTR_SEND_INPUT = 0xb2408`` from ``kbldfltr.sys``'s
``FUN_1c0007220`` at VA ``0x1c0007264``) was previously trusted purely
because its cited ``evidence_id`` existed in the run's own ledger --
``assessment_run.py``'s ``_bind_findings_to_run`` never checked whether that
evidence actually *supported* the claim. This module closes that gap for
exactly one claim type, end to end: it never trusts the model's own
argument. Given a real file, a real address (in any representation
``pe_address.py`` understands) and a claimed constant, it goes back to the
real bytes, disassembles the single real instruction at that address with
Capstone, and independently re-derives whether that instruction is a
comparison-family instruction whose immediate operand equals the claim --
the model's stated value is a hypothesis this function tests, never an
input it echoes back.

Three-way verdict, never a binary pass/fail:
  * ``VERIFIED``    -- the instruction at that address is a recognized
                        comparison-family instruction and its (width- and
                        sign-normalized) immediate operand equals the
                        claimed value.
  * ``REFUTED``      -- the address resolved and disassembled to a real,
                        definite instruction, but that instruction either
                        is not comparison-family, has no immediate operand
                        at all, or its immediate does not equal the claim.
                        This is a decisive, evidenced disproof, not a
                        shrug.
  * ``UNTESTABLE``   -- the address could not be resolved to real bytes
                        (unmapped RVA, bad kind, file unreadable), the
                        target's architecture is not one Capstone support
                        here covers, or no bytes decoded to a real
                        instruction at all. This is the harness's own
                        capability gap on this specific input, not a
                        judgement about the claim -- ``UNTESTABLE`` must
                        never be treated as, or silently become, ``FAIL``.

Recognized comparison-family mnemonics and why each is included (x86/x64
only -- the only architectures this module attempts):
  * ``cmp``, ``test`` -- the canonical compare/bit-test instructions.
  * ``sub``           -- confirmed against this harness's own real ground
                          truth: kbldfltr.sys's ``FUN_1c0007220`` dispatch
                          chain is compiled as
                          ``sub eax, 0xb2408 / je ...`` per case, not
                          ``cmp`` -- a real, repeatedly-seen MSVC/decompiler
                          switch-dispatch idiom, not a hypothetical one.
  * ``xor``           -- used the same way for an equality-by-zeroing
                          check (``xor eax, CONST / jz``), and is also the
                          home of the one zero-producing idiom this
                          verifier special-cases: ``xor reg, reg`` (same
                          register both operands) is not a comparison
                          against ``CONST`` at all, it unconditionally
                          zeroes ``reg`` -- recognized explicitly so a
                          claim of ``constant_value=0`` at such an
                          instruction is VERIFIED for the right reason
                          instead of by accident, and a nonzero claim
                          there is REFUTED rather than mis-scored.

Immediate width/sign normalization (the "split representation" this task's
brief calls out): x86 encodes ``cmp``/``sub``/``xor`` reg64/32,imm32 with a
sign-extended 32-bit (or narrower) immediate, and Capstone surfaces that as
a signed Python int -- ``cmp rax, 0xffffffff`` decodes to an immediate of
``-1``, not ``0xffffffff``, even though that is the exact same bit pattern
a claim would cite in hex. Comparing the raw signed Capstone value against
an unsigned hex literal would spuriously REFUTE a real match, so both the
disassembled immediate and the claimed value are masked to the
destination operand's real bit width (``operands[0].size`` bytes -- the
same field ``tools_stackstring.py`` already uses for its own immediate
widths) before comparing. This is the one idiom this module claims to
reconcile beyond a literal one-instruction, one-immediate compare; a
multi-instruction constant reconstruction (e.g. built up across a
``mov``/``or`` pair) is a different, unobserved-in-corpus idiom this
module deliberately does not attempt to recognize -- forcing a guess there
would violate the "never invented, never forced" contract, so that shape
falls through to ``UNTESTABLE`` (specifically ``NO_IMMEDIATE_OPERAND``) if
the instruction it lands on is a comparison-family mnemonic with only
register operands, or ``REFUTED`` if the instruction it lands on is simply
not comparison-family at all.
"""
from __future__ import annotations

from typing import Any

from pe_address import normalize_address

_COMPARISON_MNEMONICS = frozenset({"cmp", "test", "sub", "xor"})

# Machine -> (capstone arch, capstone mode). Only x86/x64 are attempted --
# the harness's own proven ioctl_code_recovery ground truth (kbldfltr.sys)
# is x64, and extending immediate-operand-family recognition to a different
# instruction set (e.g. ARM64) is real, separate work this module does not
# claim to have done.
_SUPPORTED_MACHINES = {
    0x14C: "x86_32",
    0x8664: "x86_64",
}


def _parse_claim_value(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _untestable(reason: str, **extra) -> dict:
    return {"verdict": "UNTESTABLE", "reason": reason, **extra}


def _refuted(reason: str, **extra) -> dict:
    return {"verdict": "REFUTED", "reason": reason, **extra}


def _verified(reason: str, **extra) -> dict:
    return {"verdict": "VERIFIED", "reason": reason, **extra}


def verify_constant_at_address(path, address: Any, constant_value: Any, address_kind: str = "va") -> dict:
    """Independently verify a ``constant_at_address`` claim against real
    bytes. Returns a dict always containing ``verdict`` (``VERIFIED`` /
    ``REFUTED`` / ``UNTESTABLE``) and ``reason`` (a short machine-readable
    code), plus whatever concrete evidence (resolved addresses, the actual
    disassembled instruction line, the actual immediate found) explains
    that verdict. Never raises: any real-world failure (bad address,
    unreadable file, undecodable bytes, unsupported architecture) is
    reported as ``UNTESTABLE`` with a specific ``reason``, never surfaced
    as an exception or silently turned into ``REFUTED``.
    """
    claim_int = _parse_claim_value(constant_value)
    if claim_int is None:
        return _untestable("CLAIMED_VALUE_NOT_A_NUMBER", claimed_value=constant_value)

    resolved = normalize_address(path, address, address_kind)
    if not resolved.get("ok"):
        return _untestable("ADDRESS_NOT_RESOLVED", address_resolution=resolved)

    try:
        import pefile
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OP_IMM, CS_OP_REG, Cs
    except ImportError as exc:
        return _untestable("MISSING_DEPENDENCY", detail=f"{type(exc).__name__}: {exc}")

    machine_hex = resolved["machine"]
    machine_int = int(machine_hex, 16)
    arch_name = _SUPPORTED_MACHINES.get(machine_int)
    if arch_name is None:
        return _untestable("ARCHITECTURE_NOT_SUPPORTED", machine=machine_hex)

    try:
        from pathlib import Path
        pe = pefile.PE(data=Path(path).read_bytes(), fast_load=False)
    except Exception as exc:
        return _untestable("PE_PARSE_FAILED", detail=f"{type(exc).__name__}: {exc}")

    try:
        rva = int(resolved["rva"], 16)
        va = int(resolved["va"], 16)
        # 16 bytes is enough to fully decode any one real x86/x64
        # instruction (the architecture's own maximum length is 15 bytes);
        # this reads exactly one instruction's worth of real bytes, never
        # scans backward or forward for a multi-instruction pattern.
        window = bytes(pe.get_data(rva, 16) or b"")
        if not window:
            return _untestable("NO_BYTES_AT_ADDRESS", **resolved)

        mode = CS_MODE_32 if arch_name == "x86_32" else CS_MODE_64
        decoder = Cs(CS_ARCH_X86, mode)
        decoder.detail = True

        insn = next(decoder.disasm(window, va), None)
        if insn is None:
            return _untestable("DISASSEMBLY_FAILED", **resolved, bytes_hex=window.hex())

        line = f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}".strip()
        mnemonic = insn.mnemonic.lower()

        if mnemonic not in _COMPARISON_MNEMONICS:
            return _refuted(
                "NOT_A_COMPARISON_INSTRUCTION",
                instruction=line, mnemonic=mnemonic, **resolved,
            )

        operands = list(getattr(insn, "operands", []) or [])

        # xor reg,reg (identical register both operands) unconditionally
        # zeroes the register -- it is not a comparison against
        # `constant_value` at all, it produces a known constant (0). Handle
        # this before generic immediate-operand scanning so a claim of 0 is
        # verified for the real reason, and any nonzero claim is refuted.
        if mnemonic == "xor" and len(operands) == 2 and all(op.type == CS_OP_REG for op in operands) and operands[0].reg == operands[1].reg:
            effective = 0
            if claim_int == effective:
                return _verified(
                    "ZERO_PRODUCING_XOR_IDIOM", instruction=line, effective_value=hex(effective), **resolved,
                )
            return _refuted(
                "ZERO_PRODUCING_XOR_IDIOM_VALUE_MISMATCH",
                instruction=line, effective_value=hex(effective), claimed_value=hex(claim_int) if claim_int >= 0 else claim_int,
                **resolved,
            )

        imm_operand = next((op for op in operands if op.type == CS_OP_IMM), None)
        if imm_operand is None:
            return _refuted("NO_IMMEDIATE_OPERAND_AT_ADDRESS", instruction=line, **resolved)

        # Width/sign normalization: the destination operand (operands[0]
        # for every mnemonic in _COMPARISON_MNEMONICS) carries the real
        # operand width; a narrower immediate the CPU sign-extends to fill
        # it is what Capstone reports as a signed Python int, so both sides
        # are masked to that width before comparing -- see module docstring.
        width_bytes = int(getattr(operands[0], "size", 0) or 0)
        if width_bytes <= 0:
            width_bytes = 8 if arch_name == "x86_64" else 4
        mask = (1 << (width_bytes * 8)) - 1
        actual = insn.imm if hasattr(insn, "imm") else imm_operand.imm
        actual_masked = actual & mask
        claim_masked = claim_int & mask

        if actual_masked == claim_masked:
            return _verified(
                "IMMEDIATE_MATCHES_CLAIM",
                instruction=line, immediate=hex(actual_masked), operand_width_bytes=width_bytes, **resolved,
            )
        return _refuted(
            "IMMEDIATE_VALUE_MISMATCH",
            instruction=line, immediate=hex(actual_masked), claimed_value=hex(claim_masked),
            operand_width_bytes=width_bytes, **resolved,
        )
    finally:
        try:
            pe.close()
        except Exception:
            pass
