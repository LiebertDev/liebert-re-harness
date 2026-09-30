"""Native VB6 structural inspection: the VB header chain, project objects and
their method names.

Why this exists, measured rather than assumed. Counted live across all 101
Windows-native-ladder manifests: Visual Basic is the worst-performing cohort,
1 `VERIFIED_SOLVE` out of 10 against 58% for the ladder overall, and all four
of the ladder's `CAPABILITY_GAP` entries are VB targets. Reading their evidence,
**7 of the 10 required hand-done VB structure work** -- vtable offsets, DISPID
event-dispatch jump tables, form/control identification by `.rdata` string
extraction -- repeated per target, including on the one `BLOCKED` entry
(`WNL-T2-089`). That repetition is what this replaces.

What it does NOT do, stated plainly because the distinction decides whether a
target is reachable at all: it does not decompile, and it does not interpret
P-Code. It reads the native data structures a VB6 executable carries regardless
of compile mode. That is precisely why it still works on P-Code binaries --
`WNL-T2-079` is a `CAPABILITY_GAP` P-Code target whose object table nonetheless
yields `frmMain`, `Module1` and an `MD5` class with 23 named methods. The
bodies stay opaque; the map does not.

Evidence level: this is **observed fact** from the target's own bytes. No
emulation, no execution, no synthetic anything -- a static parse of on-disk
structures, the same rung as `pe_imports` or `native_inspect`. It is not a
behavioural claim; an object named `modCheckKey` is a name in a table, not proof
of what that code does.

Layout provenance: the VB6 header/ProjectInfo/ObjectTable layout is publicly
documented in several places, but this implementation's field offsets were
**validated against seven real ladder binaries** before being trusted, and where
observation disagreed with a plausible reading, observation won -- see
`OBJECT_COUNT_OFFSET`.
"""
from __future__ import annotations

import json
import re
import struct

from tools_workspace import safe_path, relative

_ALLOWED_OPS = {"summary", "objects", "class_methods", "pcode_methods"}

VB_SIGNATURE = b"VB5!"

# VBHeader field offsets.
_H_RUNTIME_BUILD = 0x04
_H_LANG_DLL = 0x06
_H_SUB_MAIN = 0x2C
_H_PROJECT_INFO = 0x30
_H_FORM_COUNT = 0x44
_H_EXTERNAL_COUNT = 0x46
_H_PROJECT_DESCRIPTION = 0x58
_H_PROJECT_EXE_NAME = 0x5C

# ProjectInfo / ObjectTable field offsets.
_P_OBJECT_TABLE = 0x04
_T_OBJECT_ARRAY = 0x30
_T_PROJECT_NAME = 0x34

# The object count. Two nearby u16 fields both look like plausible counts, and
# they disagree on real binaries: on WNL-T2-085 offset 0x2A reads 3 while 0x2C
# reads 7. Iterating 0x2C walks past the real array into misaligned reads that
# pick up unrelated nearby strings (index 3 produced a 32-hex-character token,
# index 6 an unrelated symbol, indices 4/5/7+ empty) -- plausible-looking
# garbage, which is the dangerous kind. Offset 0x2A produced exactly the real
# objects and nothing after them on every one of the seven binaries checked.
# Observation beats the more optimistic reading.
OBJECT_COUNT_OFFSET = 0x2A

_OBJECT_STRIDE = 0x30
_O_NAME = 0x18
_O_METHOD_COUNT = 0x1C
_O_METHOD_NAMES = 0x20

MAX_OBJECTS = 256
MAX_METHODS_PER_OBJECT = 512


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


class _Image:
    """Read-only VA-addressed view over a PE. Never loaded, never executed."""

    def __init__(self, path):
        import pefile

        self.pe = pefile.PE(str(path), fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase

    def close(self):
        try:
            self.pe.close()
        except Exception:  # noqa: BLE001
            pass

    def whole(self):
        """The mapped image, so a pattern can be searched once rather than
        section by section."""
        if getattr(self, "_whole", None) is None:
            size = self.pe.OPTIONAL_HEADER.SizeOfImage
            buffer = bytearray(size)
            for section in self.pe.sections:
                raw_data = section.get_data()[:section.SizeOfRawData]
                start = section.VirtualAddress
                buffer[start:start + len(raw_data)] = raw_data
            self._whole = bytes(buffer)
        return self._whole

    def contains(self, va):
        return self.base <= va < self.base + self.pe.OPTIONAL_HEADER.SizeOfImage

    def read(self, va, size):
        if va is None or va < self.base:
            return b""
        try:
            return self.pe.get_data(va - self.base, size)
        except Exception:  # noqa: BLE001 - an unmapped VA is data, not a crash
            return b""

    def u32(self, va):
        raw = self.read(va, 4)
        return struct.unpack("<I", raw)[0] if len(raw) == 4 else None

    def u16(self, va):
        raw = self.read(va, 2)
        return struct.unpack("<H", raw)[0] if len(raw) == 2 else None

    def cstr(self, va, limit=192):
        raw = self.read(va, limit)
        if not raw:
            return ""
        end = raw.find(b"\x00")
        text = raw[: end if end >= 0 else limit]
        try:
            return text.decode("latin-1")
        except Exception:  # noqa: BLE001
            return ""


def _find_vb_header(image):
    """Locate the VBHeader.

    Preferred route is the entry point itself: a native VB6 executable begins
    `push <VBHeader>; call ThunRTMain`, so the pushed immediate IS the header
    address and needs no searching. Falls back to a signature scan for binaries
    whose entry point has been redirected (a packer, typically).
    """
    entry = image.base + image.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    head = image.read(entry, 16)
    if len(head) >= 5 and head[0] == 0x68:
        candidate = struct.unpack("<I", head[1:5])[0]
        if image.read(candidate, 4) == VB_SIGNATURE:
            return candidate, "entry_point_push"
    for section in image.pe.sections:
        try:
            data = section.get_data()
        except Exception:  # noqa: BLE001
            continue
        index = data.find(VB_SIGNATURE)
        if index >= 0:
            return image.base + section.VirtualAddress + index, "signature_scan"
    return None, None


def _objects(image, object_table, with_addresses=False):
    ranges = _executable_ranges(image) if with_addresses else []
    array = image.u32(object_table + _T_OBJECT_ARRAY)
    count = image.u16(object_table + OBJECT_COUNT_OFFSET) or 0
    rows = []
    for index in range(min(count, MAX_OBJECTS)):
        base = array + index * _OBJECT_STRIDE if array else None
        if base is None:
            break
        method_count = image.u32(base + _O_METHOD_COUNT)
        names_ptr = image.u32(base + _O_METHOD_NAMES)
        methods = []
        if names_ptr and method_count and method_count <= MAX_METHODS_PER_OBJECT:
            for slot in range(method_count):
                pointer = image.u32(names_ptr + 4 * slot)
                methods.append(image.cstr(pointer) if pointer else "")
        addresses = []
        table_va = None
        if with_addresses and method_count:
            table_va = _find_method_table(
                image, image.u32(base + 0x00), method_count, ranges)
            if table_va:
                for slot in range(method_count):
                    thunk = image.u32(table_va + 4 * slot)
                    body, via_thunk = _resolve_thunk(image, thunk, ranges)
                    addresses.append({
                        "index": slot,
                        "name": methods[slot] if slot < len(methods) else "",
                        "thunk": hex(thunk) if thunk else None,
                        "body": hex(body) if body else None,
                        "resolved_through_jmp": via_thunk,
                    })
        row = {
            "name": image.cstr(image.u32(base + _O_NAME)),
            "method_count": method_count,
            # Empty entries are real and are kept rather than filtered: VB6
            # leaves a name pointer null for methods it does not name (event
            # handlers, most commonly), and silently dropping them would
            # misreport how many methods an object actually has.
            "method_names": methods,
            "named_methods": sum(1 for name in methods if name),
        }
        if with_addresses:
            row["method_table_va"] = hex(table_va) if table_va else None
            row["method_addresses"] = addresses
            row["method_address_basis"] = (
                "HEURISTIC: a run of exactly method_count consecutive executable "
                "pointers near the ObjectInfo, each resolved through at most one jmp. "
                "Accepted only when exactly one such run exists, so an ambiguous "
                "window reports nothing rather than guessing. The table stores THUNK "
                "addresses; each body address is reached by resolving one relative jmp "
                "and is therefore never stored as a dword in the file. Covers compiled "
                "class methods and form event handlers alike."
            ) if table_va else (
                "NOT_FOUND: no unambiguous run of method_count executable pointers "
                "near this object's ObjectInfo. Reported as absent rather than "
                "approximated."
            )
        rows.append(row)
    return rows, count



# ---------------------------------------------------------------------------
# Compiled-class method address recovery
#
# WNL-T2-085 recorded this exact blocker: "Recovering Cls_Password's real
# methods (and therefore the actual serial-derivation algorithm and a working
# input) would require VB6 compiled-class-object-model-aware tooling that this
# harness does not currently have." Its own analysis had TESTED AND DISPROVED
# the natural flat-vtable-at-offset-0x0c hypothesis, so this does not retry it.
#
# What actually works, found empirically rather than from a layout document: a
# compiled class's methods are reached through a table of THUNKS sitting near
# the ObjectInfo. Each entry is `jmp <body>`. The table is located by its own
# shape -- a run of exactly `method_count` consecutive pointers, every one of
# which lands in an executable section -- which is why no fixed offset is
# hardcoded here. Offsets varied across the binaries checked; the shape did not.
#
# This is a HEURISTIC and is labelled as one in the output. It is accepted only
# when exactly one run of the right length exists in the window, so an ambiguous
# match reports nothing rather than guessing between candidates.
#
# It DOES also recover form event handlers, and the reason is worth stating
# because it was got wrong twice before being measured properly. What the table
# stores is the THUNK address, not the body address. The thunk is `jmp <body>`
# with a RELATIVE displacement, so the body address genuinely appears nowhere in
# the file as a stored dword -- searching for it finds nothing, which is what
# made the first two readings conclude event handlers were out of reach.
# Resolving one jmp hop is what bridges the two facts.
#
# Verified on WNL-T2-089, a BLOCKED target: its table entry [0] holds thunk
# 0x401c20, which resolves to 0x4022c0 -- byte-for-byte the 'Verify' handler
# that target's own analysis found by hand-tracing the DISPID jump table.

_METHOD_TABLE_WINDOW = 0x400
_MAX_THUNK_BYTES = 16


def _executable_ranges(image):
    ranges = []
    for section in image.pe.sections:
        if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            start = image.base + section.VirtualAddress
            ranges.append((start, start + max(section.Misc_VirtualSize, section.SizeOfRawData)))
    return ranges


def _is_executable(va, ranges):
    return va is not None and any(low <= va < high for low, high in ranges)


def _resolve_thunk(image, va, ranges=None):
    """Follow at most ONE jmp. A compiled-class entry is `jmp <body>`; anything
    else is returned unchanged rather than chased, so a non-thunk cannot be
    silently rewritten into something that looks resolved.

    A resolved body that does not land in an executable section is not a body.
    That happens when the method-table locator has matched a run of pointers
    that is not really a method table -- `WNL-T2-071` produced `0xcd2a1ebe` this
    way, an address outside the image reported as if it were code. Returning the
    thunk unresolved there is the honest answer: the caller sees
    `resolved_through_jmp: false` and knows nothing was followed."""
    try:
        import capstone
    except ImportError:
        return va, False
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for instruction in decoder.disasm(image.read(va, _MAX_THUNK_BYTES), va):
        if instruction.mnemonic == "jmp" and instruction.op_str.startswith("0x"):
            body = int(instruction.op_str, 16)
            if ranges is not None and not _is_executable(body, ranges):
                return va, False
            return body, True
        break
    return va, False


def _looks_like_method_entry(image, va, ranges):
    """Is this address the start of a VB6 method-table entry?

    Being executable is not enough, and assuming it was produced confident
    nonsense. A compiled-class entry is a `jmp <body>` thunk; a P-Code method
    starts with one of the two interpreter stubs, whose first instruction is
    `xor eax, eax` or `mov edx, <descriptor>`. Measured across the corpus, every
    entry of a real table matches one of those, and every entry of a false match
    fails: WNL-T2-071's three "tables" gave `jmp 0xcd2a1ebe` (a target outside
    the image), `sahf`, `push eax` and `add byte ptr [eax], al`, and one of them
    sat inside the ProjectInfo structure rather than in code at all.
    """
    try:
        import capstone
    except ImportError:
        return True  # no decoder, no opinion -- do not reject on ignorance
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for instruction in decoder.disasm(image.read(va, 12), va):
        if instruction.mnemonic == "jmp" and instruction.op_str.startswith("0x"):
            return _is_executable(int(instruction.op_str, 16), ranges)
        if instruction.mnemonic == "xor" and instruction.op_str == "eax, eax":
            return True
        if instruction.mnemonic == "mov" and instruction.op_str.startswith("edx, 0x"):
            return True
        return False
    return False


def _find_method_table(image, object_info, method_count, ranges):
    """Locate a run of exactly `method_count` consecutive method-table entries."""
    if not object_info or not method_count or method_count < 2:
        return None
    matches = []
    va = object_info - _METHOD_TABLE_WINDOW
    run_start, run_length = None, 0
    end = object_info + _METHOD_TABLE_WINDOW
    while va < end:
        if _is_executable(image.u32(va), ranges):
            if run_start is None:
                run_start, run_length = va, 0
            run_length += 1
        else:
            if run_length == method_count:
                matches.append(run_start)
            run_start, run_length = None, 0
        va += 4
    if run_length == method_count and run_start is not None:
        matches.append(run_start)
    # A run of executable pointers is a candidate, not a table. Keep only the
    # ones whose every entry actually looks like a method entry.
    matches = [start for start in matches
               if all(_looks_like_method_entry(image, image.u32(start + 4 * slot), ranges)
                      for slot in range(method_count))]
    # Exactly one candidate, or nothing. An ambiguous match is not a match.
    return matches[0] if len(matches) == 1 else None


# A P-Code method is not native code. What sits at its entry is a three
# instruction stub that hands the interpreter a descriptor and jumps into it:
#
#     mov edx, <descriptor>      BA imm32
#     mov ecx, <engine thunk>    B9 imm32
#     jmp ecx                    FF E1
#
# Finding those stubs is what tells a reader where the compiled procedures are
# in a binary whose .text carries almost no real code. It does NOT decode the
# P-Code stream -- that needs an opcode table this project does not have, and
# saying so is the point: the operation reports the entry points it can prove
# and names what it cannot do.
# Two stub shapes reach the same place. The first is the one this scanner was
# built on: `mov edx, <descriptor>; mov ecx, <engine>; jmp ecx`. The second
# reaches the engine through a `push`/`ret` trampoline and begins by zeroing
# eax: `xor eax, eax; mov edx, <descriptor>; push <engine>; ret`. Measured on
# WNL-T2-079, where the first shape matches nothing and the second matches 33
# stubs -- a target that read as "not P-Code" only because of the shape scanned
# for. Both are recorded with the shape that matched, so the distinction stays
# visible rather than being flattened.
_PCODE_STUBS = (
    ("mov_ecx_jmp",
     re.compile(bytes([0xBA]) + b'(....)' + bytes([0xB9]) + b'(....)'
                + bytes([0xFF, 0xE1]), re.S), 0),
    ("push_ret",
     re.compile(bytes([0x33, 0xC0, 0xBA]) + b'(....)' + bytes([0x68]) + b'(....)'
                + bytes([0xC3]), re.S), 0),
)


def _pcode_methods(image):
    blob = image.whole()
    if not blob:
        return [], []
    found = []
    for shape, pattern, _reserved in _PCODE_STUBS:
        for match in pattern.finditer(blob):
            descriptor = struct.unpack("<I", match.group(1))[0]
            engine = struct.unpack("<I", match.group(2))[0]
            stub = image.base + match.start()
            if not image.contains(descriptor) or not image.contains(engine):
                continue
            found.append({"stub_va": hex(stub), "descriptor_va": hex(descriptor),
                          "interpreter_thunk_va": hex(engine),
                          "stub_shape": shape,
                          "descriptor_head": image.read(descriptor, 16).hex()})
    found.sort(key=lambda entry: int(entry["stub_va"], 16))
    engines = sorted({entry["interpreter_thunk_va"] for entry in found})
    return found, engines


def vb6_inspect(path, operation="summary", max_chars=60000):
    """Parse a native VB6 executable's header chain and project object table."""
    if operation not in _ALLOWED_OPS:
        return _j({"ok": False, "error": "UNKNOWN_OPERATION", "tool": "vb6_inspect",
                   "allowed": sorted(_ALLOWED_OPS)})
    try:
        import pefile  # noqa: F401
    except ImportError:
        return _j({"ok": False, "status": "TOOL_MISSING", "tool": "vb6_inspect",
                   "required_capability": "pefile"})

    target = safe_path(path)
    try:
        image = _Image(target)
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "status": "NOT_A_PE", "tool": "vb6_inspect",
                   "path": relative(target), "error": f"{type(exc).__name__}: {exc}"})

    try:
        header, how = _find_vb_header(image)
        if header is None:
            return _j({
                "ok": False, "status": "NOT_VISUAL_BASIC", "tool": "vb6_inspect",
                "path": relative(target),
                "detail": "no VB5! header reachable from the entry point or any section",
            })

        project_info = image.u32(header + _H_PROJECT_INFO)
        object_table = image.u32(project_info + _P_OBJECT_TABLE) if project_info else None
        result = {
            "ok": True, "status": "OK", "tool": "vb6_inspect", "operation": operation,
            "path": relative(target),
            "vb_header_va": hex(header),
            "vb_header_found_via": how,
            "runtime_build": image.u16(header + _H_RUNTIME_BUILD),
            "runtime_dll": image.cstr(header + _H_LANG_DLL, 14),
            "sub_main_va": hex(image.u32(header + _H_SUB_MAIN) or 0),
            "form_count": image.u16(header + _H_FORM_COUNT),
            "external_count": image.u16(header + _H_EXTERNAL_COUNT),
            "project_exe_name": image.cstr(image.u32(header + _H_PROJECT_EXE_NAME) or 0),
            "project_description": image.cstr(image.u32(header + _H_PROJECT_DESCRIPTION) or 0),
            "project_info_va": hex(project_info or 0),
            "object_table_va": hex(object_table or 0),
            "evidence_class": "observed_fact",
            "evidence_note": (
                "Static parse of the target's own on-disk structures. No execution, no "
                "emulation. Object and method NAMES are facts about the binary's tables; "
                "they are not claims about behaviour."
            ),
            "limitations": [
                "Structure only -- no decompilation and no P-Code interpretation.",
                "Method-name slots are frequently empty: VB6 leaves the name pointer null "
                "for unnamed methods (event handlers most often). Empty entries are "
                "reported rather than dropped so method_count stays truthful.",
                "Object count is read from the empirically-validated field; see "
                "OBJECT_COUNT_OFFSET in tools_vb6.py for why the larger nearby field is "
                "not used.",
            ],
        }
        if object_table:
            result["project_name"] = image.cstr(image.u32(object_table + _T_PROJECT_NAME) or 0)
            if operation == "objects" or True:
                rows, count = _objects(
                    image, object_table, with_addresses=(operation == "class_methods"))
                result["object_count"] = count
                result["objects"] = rows if operation in {"objects", "class_methods"} else [
                    {"name": row["name"], "method_count": row["method_count"],
                     "named_methods": row["named_methods"]}
                    for row in rows
                ]
        if operation == "pcode_methods":
            stubs, engines = _pcode_methods(image)
            result["pcode_method_stubs"] = stubs
            result["pcode_method_count"] = len(stubs)
            result["interpreter_thunks"] = engines
            # Finding a stub proves P-Code. NOT finding one proves nothing: the
            # shape below is one of several, and a form-based project with no
            # Sub Main reaches its procedures another way -- WNL-T2-079 is a
            # confirmed P-Code binary that this scan finds no stubs in. Saying
            # "native" there would be a verdict the evidence does not support.
            result["stub_scan"] = "STUBS_FOUND" if stubs else "NO_STUBS_OF_THIS_SHAPE"
            result["compiled_as"] = "P_CODE" if stubs else "UNDETERMINED_BY_THIS_SCAN"
            result["not_established"] = [
                "THE_MEANING_OF_ANY_P_CODE_BYTE",
                "WHICH_SOURCE_PROCEDURE_A_STUB_BELONGS_TO",
            ] + ([] if stubs else ["THAT_THIS_BINARY_IS_NATIVE_RATHER_THAN_P_CODE"])
            result["what_this_does_not_do"] = (
                "It locates the entry stubs and their descriptors. It does not decode the "
                "P-Code stream: that needs an opcode table this project does not have, and "
                "guessing one would produce a plausible wrong listing, which is the failure "
                "this harness exists to avoid. An empty result is a statement about this "
                "stub shape only, never about how the binary was compiled."
            )
        rendered = _j(result)
        while len(rendered) > max_chars and result.get("objects"):
            result["objects"].pop()
            result["truncated"] = True
            rendered = _j(result)
        return rendered
    finally:
        image.close()
