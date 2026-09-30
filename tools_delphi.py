"""Borland/Embarcadero Delphi class recovery from a compiled 32-bit binary.

A Delphi class is not discoverable from strings or imports. Its identity lives
in a **VMT** -- a table of method pointers with a fixed block of negative-offset
slots in front of it:

    vmtSelfPtr      -76     vmtClassName    -44
    vmtIntfTable    -72     vmtInstanceSize -40
    vmtAutoTable    -68     vmtParent       -36
    vmtInitTable    -64
    vmtTypeInfo     -60
    vmtFieldTable   -56
    vmtMethodTable  -52
    vmtDynamicTable -48

`vmtSelfPtr` holds the address of its own VMT, which makes it a signature rather
than a heuristic: a dword at address A qualifies only when it contains exactly
`A + 76`, and the class name it then points at must be a well-formed
ShortString. Nothing here guesses.

**Why this exists.** The ladder's Delphi entries were analysed by chasing
strings and imports, and `WNL-T2-072` records that route reaching a dead end:
Delphi sets a control's caption through VCL property streaming rather than an
instruction referencing the literal, so string cross-referencing -- which had
located the check in every C/C++ and VB6 target before it -- finds nothing. The
class table is the structural answer to that.

**What it does not do.** It does not decompile, and it does not parse the
published-method table. That parser is deliberately absent rather than written
untested: every Delphi binary in this corpus has `vmtMethodTable = 0` on all 48
of its classes, so there is no fixture to validate one against, and shipping an
unexercised parser is how a tool starts lying. The pointer is reported so a
caller can see the table is empty for itself.

Evidence rung: `observed_fact`. This is a static parse of the target's own
bytes -- nothing is executed, emulated, or inferred from behaviour.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

from tools_workspace import safe_path, relative

_ALLOWED_OPS = {"classes"}

# Negative offsets from the VMT, classic Delphi 2 through modern 32-bit.
VMT_SELF_PTR = -76
VMT_METHOD_TABLE = -52
VMT_DYNAMIC_TABLE = -48
VMT_CLASS_NAME = -44
VMT_INSTANCE_SIZE = -40
VMT_PARENT = -36
VMT_FIELD_TABLE = -56
VMT_TYPE_INFO = -60

MAX_CLASSES = 4096


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2)


class _Image:
    """Read-only VA-addressed view over a PE. Never loaded, never executed."""

    def __init__(self, path):
        import pefile

        self.pe = pefile.PE(str(path), fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        size = self.pe.OPTIONAL_HEADER.SizeOfImage
        buffer = bytearray(size)
        for section in self.pe.sections:
            raw = section.get_data()[:section.SizeOfRawData]
            start = section.VirtualAddress
            if 0 <= start < size:
                buffer[start:start + len(raw)] = raw
        self.data = bytes(buffer)

    def close(self):
        try:
            self.pe.close()
        except Exception:  # noqa: BLE001
            pass

    def dword(self, va):
        offset = va - self.base
        if 0 <= offset <= len(self.data) - 4:
            return struct.unpack_from("<I", self.data, offset)[0]
        return None

    def short_string(self, va):
        """Delphi stores a class name as a length byte followed by its text."""
        if va is None:
            return None
        offset = va - self.base
        if not (0 <= offset < len(self.data)):
            return None
        length = self.data[offset]
        if length == 0 or offset + 1 + length > len(self.data):
            return None
        raw = self.data[offset + 1:offset + 1 + length]
        if not all(32 <= byte < 127 for byte in raw):
            return None
        return raw.decode("latin-1")


def _scan(image):
    """Every VMT whose self-pointer and class name both check out."""
    found = []
    data, base = image.data, image.base
    for offset in range(0, len(data) - 4, 4):
        value = struct.unpack_from("<I", data, offset)[0]
        if value != base + offset - VMT_SELF_PTR:
            continue
        vmt = value
        name = image.short_string(image.dword(vmt + VMT_CLASS_NAME))
        if not name:
            continue
        found.append({
            "vmt_va": hex(vmt),
            "name": name,
            "instance_size": image.dword(vmt + VMT_INSTANCE_SIZE),
            "parent_vmt_va": _hex_or_none(image.dword(vmt + VMT_PARENT)),
            "method_table_va": _hex_or_none(image.dword(vmt + VMT_METHOD_TABLE)),
            "dynamic_table_va": _hex_or_none(image.dword(vmt + VMT_DYNAMIC_TABLE)),
            "field_table_va": _hex_or_none(image.dword(vmt + VMT_FIELD_TABLE)),
            "type_info_va": _hex_or_none(image.dword(vmt + VMT_TYPE_INFO)),
        })
        if len(found) >= MAX_CLASSES:
            break
    return found


def _hex_or_none(value):
    return hex(value) if value else None


def _link_parents(classes, image):
    """Turn parent pointers into names where the parent is in this image.

    `vmtParent` does not hold the parent's VMT. It holds the address of a slot
    that holds it, so resolving the hierarchy takes one dereference -- reading
    it directly leaves every class looking like a root, which is how this was
    caught."""
    by_vmt = {entry["vmt_va"]: entry["name"] for entry in classes}
    for entry in classes:
        entry["parent_name"] = None
        slot = entry.get("parent_vmt_va")
        if not slot:
            continue
        parent_vmt = image.dword(int(slot, 16))
        if parent_vmt:
            entry["parent_name"] = by_vmt.get(hex(parent_vmt))
    return classes


def delphi_inspect(path, operation="classes", max_chars=60000):
    """Recover Delphi classes from a compiled binary's VMT structures."""
    if operation not in _ALLOWED_OPS:
        return _j({"ok": False, "error": "UNKNOWN_OPERATION", "tool": "delphi_inspect",
                   "allowed": sorted(_ALLOWED_OPS)})
    try:
        import pefile  # noqa: F401
    except ImportError:
        return _j({"ok": False, "status": "TOOL_MISSING", "tool": "delphi_inspect",
                   "required_capability": "pefile"})

    target = safe_path(path)
    try:
        image = _Image(target)
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "status": "NOT_A_PE", "tool": "delphi_inspect",
                   "path": relative(target), "error": f"{type(exc).__name__}: {exc}"})

    try:
        classes = _link_parents(_scan(image), image)
        with_methods = [entry for entry in classes if entry["method_table_va"]]
        result = {
            "ok": True,
            "status": "OK",
            "tool": "delphi_inspect",
            "operation": operation,
            "path": relative(target),
            "image_base": hex(image.base),
            "class_count": len(classes),
            "classes_with_a_published_method_table": len(with_methods),
            "classes": classes,
            "evidence_class": "observed_fact",
            "evidence_note": (
                "Static parse of the target's own bytes. A VMT is accepted only when its "
                "vmtSelfPtr slot contains the VMT's own address and vmtClassName resolves to "
                "a printable ShortString, so a match is a structure the file carries, not a "
                "pattern that resembled one."
            ),
            "not_established": [
                "WHAT_ANY_METHOD_DOES",
                "WHICH_CLASS_IMPLEMENTS_THE_PROGRAM'S_CHECK",
            ],
            "what_this_does_not_do": (
                "No decompilation, and no published-method-table parsing: that parser is "
                "absent rather than untested, because every Delphi binary in this corpus "
                "reports vmtMethodTable = 0 on every class, leaving nothing to validate one "
                "against. The pointer is reported so a caller can see that for itself."
            ),
        }
        if not classes:
            result["not_established"].append(
                "THAT_THIS_BINARY_IS_NOT_DELPHI")
            result["absence_note"] = (
                "No VMT matched. That is a statement about this signature, not a verdict on "
                "the compiler: a packed or stub binary carries no readable class table, and "
                "Borland-style section names alone do not make a file a Delphi application."
            )
        rendered = _j(result)
        while len(rendered) > max_chars and result["classes"]:
            result["classes"] = result["classes"][:len(result["classes"]) // 2]
            result["classes_truncated"] = True
            rendered = _j(result)
        return rendered
    finally:
        image.close()
