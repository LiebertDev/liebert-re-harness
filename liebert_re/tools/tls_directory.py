"""Parse a PE's TLS directory (``IMAGE_DIRECTORY_ENTRY_TLS``) and its
callback array -- a real blind spot: TLS callbacks run BEFORE the process
entry point, which is exactly where anti-debug checks and unpacking stubs
hide, and nothing in this codebase's fast static path surfaced them (only
Ghidra named them incidentally, when it happened to disassemble that far).

Uses ``pefile`` for the directory/array parsing and reuses
``pe_address.resolve_address_form`` for every address reported here (the
callback array's own address, and each callback's address) so this tool
never hand-computes RVA/VA/file-offset math independently of the one
shared, already-tested PE-section-table resolver every other engine
adapter in this codebase uses.

Status vocabulary (every one of these is a distinct, non-empty-list-shaped
answer):
  ``NO_TLS_DIRECTORY`` -- this PE has no ``IMAGE_DIRECTORY_ENTRY_TLS`` at
    all. Explicit, never conflated with "has a TLS directory with zero
    callbacks" (see below) -- a caller must be able to tell "not present"
    from "present but empty" without inspecting anything but ``status``.
  ``OK`` -- a TLS directory exists. ``callback_count`` and ``callbacks``
    report the truth, which can legitimately be zero: a TLS directory with
    ``AddressOfCallBacks == 0`` (no callback array at all -- observed on a
    real Delphi target in this corpus) is reported as ``callbacks: []``
    with ``callback_array_address: null`` and ``note`` explaining why, NOT
    as an error and NOT silently indistinguishable from "we failed to read
    it".
  ``UNSUPPORTED_ARCHITECTURE`` -- a TLS directory exists but the machine
    type is not one this module was verified on (i386, amd64); refused
    rather than guessing a pointer width. ``UNSUPPORTED_OPTIONAL_HEADER`` /
    ``PE_HEADER_INCONSISTENT`` -- magic is not PE32/PE32+, or disagrees with
    the machine type. Pointer width comes from the optional-header magic.
  ``TOOL_MISSING`` -- ``pefile`` not importable.
  ``NOT_A_PE`` / ``NOT_FOUND`` / ``PATH_REFUSED`` -- as every other tool in
    this codebase.
"""
from __future__ import annotations

import json
from pathlib import Path

from liebert_re.recover.pe_address import resolve_address_form
from liebert_re.workspace import safe_path, relative

_MAX_CALLBACKS = 256  # runaway/corrupt-data guard, not a real-world limit
_FIRST_BYTES_LEN = 16
_MAGIC_PTR_SIZE = {0x10B: 4, 0x20B: 8}  # PE32, PE32+
# Machine types this module has been exercised on -> (name, expected magic).
_SUPPORTED_MACHINES = {0x14C: ("i386", 0x10B), 0x8664: ("amd64", 0x20B)}


def _j(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _open_pe(path: Path):
    import pefile

    data = path.read_bytes()
    return pefile.PE(data=data, fast_load=False)


def _address_form(path: Path, va: int) -> dict:
    form, err = resolve_address_form(str(path), hex(va), "va")
    if form is None:
        return {"resolved": False, "va": hex(va), "error": err.get("error") if err else "UNKNOWN"}
    result = form.to_dict()
    result["resolved"] = True
    return result


def analyze_tls_directory(path):
    """Report, for one PE, whether an ``IMAGE_DIRECTORY_ENTRY_TLS`` exists,
    the callback array's own address (in every ``pe_address.AddressForm``
    representation), and for each real callback pointer: its address (same
    five representations) plus the raw first bytes read directly from the
    file at that address, so a caller can see it is real code without a
    second round-trip.

    Never raises for a malformed/absent directory or an unmapped callback
    pointer -- those are reported as explicit, named conditions (see the
    module docstring's status vocabulary), never a silent empty success.
    """
    try:
        p = safe_path(path)
    except PermissionError as exc:
        return _j({"ok": False, "tool": "analyze_tls_directory", "status": "PATH_REFUSED", "error": str(exc)})
    if not p.is_file():
        return _j({"ok": False, "tool": "analyze_tls_directory", "status": "NOT_FOUND", "path": str(path)})

    try:
        import pefile  # noqa: F401
    except ImportError:
        return _j({"ok": False, "tool": "analyze_tls_directory", "status": "TOOL_MISSING", "required_capability": "pefile (pip install pefile)"})

    try:
        pe = _open_pe(p)
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "tool": "analyze_tls_directory", "status": "NOT_A_PE", "error": f"{type(exc).__name__}: {exc}"})

    try:
        # Checked before the directory lookup: with an unrecognised magic
        # pefile parses no data directories, so "no TLS directory" would be a
        # confident wrong answer.
        if int(pe.OPTIONAL_HEADER.Magic) not in _MAGIC_PTR_SIZE:
            return _j({
                "ok": False, "tool": "analyze_tls_directory", "status": "UNSUPPORTED_OPTIONAL_HEADER",
                "path": relative(p), "machine": hex(int(pe.FILE_HEADER.Machine)),
                "optional_header_magic": hex(int(pe.OPTIONAL_HEADER.Magic)),
                "error": "optional-header magic is neither PE32 (0x10b) nor PE32+ (0x20b)",
            })
        tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if tls is None:
            return _j({
                "ok": True, "tool": "analyze_tls_directory", "status": "NO_TLS_DIRECTORY",
                "path": relative(p), "has_tls_directory": False,
            })

        s = tls.struct
        image_base = pe.OPTIONAL_HEADER.ImageBase
        machine = int(pe.FILE_HEADER.Machine)
        magic = int(pe.OPTIONAL_HEADER.Magic)
        if machine not in _SUPPORTED_MACHINES:
            return _j({
                "ok": False, "tool": "analyze_tls_directory", "status": "UNSUPPORTED_ARCHITECTURE",
                "path": relative(p), "machine": hex(machine), "optional_header_magic": hex(magic),
                "supported_machines": {hex(m): n for m, (n, _) in _SUPPORTED_MACHINES.items()},
                "error": "callback-array width is only verified for the listed machine types",
            })
        if magic != _SUPPORTED_MACHINES[machine][1]:
            return _j({
                "ok": False, "tool": "analyze_tls_directory", "status": "PE_HEADER_INCONSISTENT",
                "path": relative(p), "machine": hex(machine), "optional_header_magic": hex(magic),
                "error": "machine type and optional-header magic disagree about pointer width",
            })
        # The PE format defines pointer width by the optional-header magic
        # (PE32 = 4 bytes, PE32+ = 8), not by the machine field.
        ptr_size = _MAGIC_PTR_SIZE[magic]
        ptr_fmt = "<Q" if ptr_size == 8 else "<I"

        cb_va = int(s.AddressOfCallBacks)
        directory = {
            "start_address_of_raw_data": hex(int(s.StartAddressOfRawData)),
            "end_address_of_raw_data": hex(int(s.EndAddressOfRawData)),
            "address_of_index": hex(int(s.AddressOfIndex)),
            "address_of_callbacks": hex(cb_va),
            "size_of_zero_fill": int(s.SizeOfZeroFill),
            "characteristics": hex(int(s.Characteristics)),
        }

        callbacks = []
        callback_array_address = None
        note = None

        if cb_va == 0:
            note = "AddressOfCallBacks is NULL -- this TLS directory has no callback array at all"
        else:
            callback_array_address = _address_form(p, cb_va)
            if not callback_array_address.get("resolved"):
                note = "AddressOfCallBacks does not resolve to any section -- cannot read the callback array"
            else:
                import struct

                rva = cb_va - image_base
                offset = 0
                while len(callbacks) < _MAX_CALLBACKS:
                    try:
                        raw_ptr = pe.get_data(rva + offset, ptr_size)
                    except Exception:
                        note = f"callback array read stopped at index {len(callbacks)} -- ran past mapped data"
                        break
                    if len(raw_ptr) < ptr_size:
                        note = f"callback array read stopped at index {len(callbacks)} -- ran past mapped data"
                        break
                    (entry_va,) = struct.unpack(ptr_fmt, raw_ptr)
                    if entry_va == 0:
                        break  # NUL-terminated array, the normal, expected end
                    entry = {"address": _address_form(p, entry_va)}
                    if entry["address"].get("resolved"):
                        entry_rva = entry_va - image_base
                        try:
                            first_bytes = pe.get_data(entry_rva, _FIRST_BYTES_LEN)
                        except Exception:
                            first_bytes = b""
                        entry["first_bytes"] = first_bytes.hex()
                    else:
                        entry["first_bytes"] = None
                        entry["error"] = "callback address does not resolve to any section"
                    callbacks.append(entry)
                    offset += ptr_size

        payload = {
            "ok": True, "tool": "analyze_tls_directory", "status": "OK",
            "path": relative(p), "has_tls_directory": True,
            "machine": hex(pe.FILE_HEADER.Machine), "pointer_size": ptr_size,
            "image_base": hex(image_base),
            "directory": directory,
            "callback_array_address": callback_array_address,
            "callback_count": len(callbacks),
            "callbacks": callbacks,
        }
        if note:
            payload["note"] = note
        return _j(payload)
    finally:
        try:
            pe.close()
        except Exception:
            pass
