"""Deterministic RVA / VA / file-offset normalization for PE binaries.

GAP-061 step 1 (see docs/PROJECT_STATE.md): evidence records produced by this
harness's own tools store addresses in mixed representations -- some as an
RVA (``tools_stackstring.py``'s ``extract_data_blob``), some as a VA
(``tools_binary.disassemble_pe``'s ``va`` parameter, ``ioctl_recovery.py``'s
function addresses). Before any deterministic verifier can go re-read real
bytes at a claimed address, it needs one small, independently-tested piece
that converts between representations *without* silently landing on the
wrong byte -- this module is that piece, used by
``constant_at_address_verifier.py``.

Every entry point here takes a real file path and a real address, opens the
PE with ``pefile`` (from owned bytes -- never ``pefile.PE(str(path))`` --
so no Windows file handle is retained after the call returns, same
convention ``tools_stackstring.py`` and ``tools_binary.py`` already use),
and returns a structured result: ``{"ok": True, ...}`` with all three
representations plus the containing section, or ``{"ok": False, "error":
...}`` with a specific reason. It never raises for a malformed or
unresolvable address and it never silently guesses -- an address this
module cannot place inside a real section is reported as unresolved, not
coerced into a nearby one.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ADDRESS_KINDS = frozenset({"va", "rva", "file_offset"})


@dataclass(frozen=True)
class AddressForm:
    """The one shared address-form contract every engine adapter (rizin's
    ``tools_rizin.py``, IDA's ``tools_ida.py``/``ida_scripts/query_program.py``,
    and any future engine) returns for EVERY address it reports -- an
    instruction's own location, a resolved branch target, or a patch site
    alike.

    This exists because a real misdiagnosis in this project traced back to
    a schema bug, not a missing tool: different call sites returned
    different subsets of file_offset/RVA/VA/section as ad-hoc dict keys, so
    a caller could not tell which representation it was holding. Fixing
    that as one small type -- instead of four ad-hoc dict keys repeated
    (and occasionally omitted) per adapter -- is the actual fix: every
    consumer reads the same five fields, produced by the same
    ``pefile``-backed PE-section-table resolver, no matter which engine
    (rizin, IDA, ...) produced them.
    """
    file_offset: str
    rva: str
    va: str
    image_base: str
    section: str

    def to_dict(self) -> dict:
        return asdict(self)


def resolve_address_form(path, address: Any, address_kind: str = "va") -> tuple["AddressForm | None", "dict | None"]:
    """Resolve one address (in any of the three representations) into the
    shared ``AddressForm`` contract via ``normalize_address`` -- the real
    PE section table, never a fixed delta or a guess. Returns
    ``(AddressForm, None)`` on success or ``(None, error_dict)`` (the same
    error vocabulary ``normalize_address`` already uses) on failure. Never
    raises."""
    resolved = normalize_address(path, address, address_kind)
    if not resolved.get("ok"):
        return None, resolved
    return AddressForm(
        file_offset=resolved["file_offset"],
        rva=resolved["rva"],
        va=resolved["va"],
        image_base=resolved["image_base"],
        section=resolved["section"],
    ), None


def _parse_addr(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _open_pe(path):
    import pefile

    p = Path(path)
    data = p.read_bytes()
    return pefile.PE(data=data, fast_load=False)


def normalize_address(path, address: Any, address_kind: str = "va") -> dict:
    """Convert one address, given in any of the three representations, into
    all three plus its containing section.

    ``address_kind`` is one of ``"va"`` (default), ``"rva"`` or
    ``"file_offset"`` -- which representation ``address`` is already in.
    Returns ``{"ok": True, "va": "0x...", "rva": "0x...",
    "file_offset": "0x...", "section": "...", "image_base": "0x..."}`` on
    success. On failure returns ``{"ok": False, "error": <reason>, ...}``
    and never raises for a bad address, bad kind, or a file pefile cannot
    parse -- those are all real, expected inputs a caller (a model's own
    claim, in particular) can hand this function, and the whole point of a
    verifier built on top of this is to turn "cannot resolve" into
    ``UNTESTABLE`` rather than a crash.
    """
    kind = str(address_kind or "va").strip().lower()
    if kind not in ADDRESS_KINDS:
        return {"ok": False, "error": "UNKNOWN_ADDRESS_KIND", "address_kind": kind, "allowed": sorted(ADDRESS_KINDS)}
    addr_int = _parse_addr(address)
    if addr_int is None or addr_int < 0:
        return {"ok": False, "error": "INVALID_ADDRESS", "address": address, "address_kind": kind}

    try:
        pe = _open_pe(path)
    except FileNotFoundError:
        return {"ok": False, "error": "FILE_NOT_FOUND", "path": str(path)}
    except Exception as exc:
        return {"ok": False, "error": "PE_PARSE_FAILED", "detail": f"{type(exc).__name__}: {exc}"}

    try:
        image_base = pe.OPTIONAL_HEADER.ImageBase

        if kind == "va":
            if addr_int < image_base:
                return {"ok": False, "error": "VA_BELOW_IMAGE_BASE", "va": hex(addr_int), "image_base": hex(image_base)}
            rva = addr_int - image_base
        elif kind == "rva":
            rva = addr_int
        else:  # file_offset
            rva = pe.get_rva_from_offset(addr_int)
            if rva is None:
                return {"ok": False, "error": "FILE_OFFSET_NOT_MAPPED", "file_offset": hex(addr_int)}

        section = pe.get_section_by_rva(rva)
        if section is None:
            return {
                "ok": False, "error": "RVA_NOT_IN_ANY_SECTION",
                "rva": hex(rva), "va": hex(image_base + rva), "image_base": hex(image_base),
            }
        try:
            file_offset = pe.get_offset_from_rva(rva)
        except Exception:
            return {"ok": False, "error": "RVA_HAS_NO_FILE_OFFSET", "rva": hex(rva)}

        return {
            "ok": True,
            "va": hex(image_base + rva),
            "rva": hex(rva),
            "file_offset": hex(file_offset),
            "section": section.Name.rstrip(b"\x00").decode(errors="replace"),
            "image_base": hex(image_base),
            "machine": hex(pe.FILE_HEADER.Machine),
        }
    finally:
        try:
            pe.close()
        except Exception:
            pass
