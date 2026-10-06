"""Correlates a dumped/recovered PE (from ANY unpacker, for ANY target) with
the live process it came from, in both directions:

  - dump-side -> live: given an RVA or a file offset inside the dump, what
    virtual address does that land at in a live process (given an explicit
    module base, or a base derived from a live-address+RVA record the
    harness already resolved elsewhere)?
  - live-side -> dump: given a live VA that was actually observed at
    runtime, where is that inside the dump file -- which section, what RVA,
    what file offset, and what bytes are there?

Every other tool in this project either produces a dump (``emulation_unpack``,
``upx_unpack``, ``unpack_iat_rebuild``, a manual guest fetch) or needs a live
address (``guest_frida_breakpoint_inspect``, ``guest_windbg_*``). Translating
between the two coordinate systems was left to the analyst doing arithmetic
by hand -- this module is that missing translation layer, and it is
deliberately format/target-agnostic: no packer name, section name, or
per-target constant appears anywhere in this file. It reads ONE file (the
dump) with ``pefile`` (an existing project dependency -- no PE parser is
written here) and does integer arithmetic; it never touches a live process,
never opens a guest transport, and never executes anything. Host-side static
analysis of a file, full stop -- the same class of tool as the other static
readers in this package (e.g. ``liebert_re/tools/binary.py``), not a tool that needs a guest VM:
this package has no guest layer.

**Why naive ``base + rva`` is wrong, and what this module does about it.**

1. **Raw vs. virtual/unmapped dump layout.** A dump on disk is either
   file-aligned ("raw" -- ``PointerToRawData`` is a genuinely different,
   smaller-stride offset than ``VirtualAddress``, as an ordinary on-disk PE
   is) or section-aligned ("virtual"/"unmapped" -- the dumper wrote the
   in-memory image out more or less verbatim, so a byte's position in the
   FILE equals its RVA, not its stale/rewritten ``PointerToRawData``). This
   module never assumes one: ``_classify_dump_layout`` compares, for every
   section that actually carries on-disk bytes, whether
   ``PointerToRawData == VirtualAddress`` (the direct, per-task-specified
   evidence), and reports the exact ratio plus the secondary
   ``FileAlignment == SectionAlignment`` signal a number of real
   dump-rebuilding tools (Scylla-class rebuilders) set as a deliberate
   marker of this case. The concluded ``kind`` ("raw"/"virtual") and the
   full per-section evidence used to reach it are always in the result
   under ``dump_layout`` -- never silently assumed. A caller who already
   knows better (e.g. from the dumping tool's own documentation) may
   override via ``dump_layout=`` and the detected kind is still reported
   alongside for comparison.
2. **ASLR / rebased dumps.** The dump's own ``OPTIONAL_HEADER.ImageBase`` is
   reported for reference but NEVER used as "the" live base -- a live base
   is only ever the caller's explicit ``live_module_base`` (or one derived,
   never invented, from a resolved live record -- see below). This is what
   makes an already-rebased dump (image base changed by the dumping tool)
   and a live ASLR base that differs from the file's own header both work
   correctly: the correlation is always RVA-relative, ``live_va =
   live_module_base + rva``, independent of whatever the dump's own
   ``ImageBase`` field happens to say.
3. **Zero-raw-size sections holding live code.** A section can have
   ``SizeOfRawData == 0`` (nothing on disk at that RVA range -- exactly what
   an UPX-class packer's own decompression target section looks like before
   unpacking) while still being a real, addressable part of the image at
   runtime. This is reported as its own explicit ``NO_RAW_DATA_ON_DISK``
   file-offset status: the RVA/live-VA correlation still succeeds (it is
   pure arithmetic), only the file-offset/byte-preview half of the answer
   is honestly absent, with a reason -- never a fabricated offset.
4. **Out-of-range and inter-section gaps.** An RVA/offset/VA that does not
   fall inside the PE header region or any section's mapped extent is
   ``UNMAPPED_RVA``/``UNMAPPED_FILE_OFFSET``/``UNMAPPED_LIVE_ADDRESS``
   (``ok: false``) -- NEVER a plausible-looking computed number. This
   applies equally to addresses past the end of the image and to addresses
   that fall in the padding gap between two sections.

**Composing with ``guest_frida_breakpoint_inspect`` without duplicating it.**
That tool (``tools_frida_breakpoints.py`` -> ``breakpoint_inspect.js``)
already resolves a live module base at runtime and reports it embedded in
every ``attached``/``hits`` record as ``{"address": "0x...", "module":
"...", "rva": "0x..."}`` (module-relative ``rva`` plus the absolute
``address`` it resolved to -- see that module's docstring/JS agent). Rather
than re-deriving that resolution here (which would mean opening a second
guest transport, exactly what this module must NOT do), ``live_module_base``
accepts that exact record shape -- a single record, or the full
``breakpoint_inspect`` result payload (its ``attached``/``hits`` lists are
searched for the first usable entry) -- and derives ``base = address - rva``
from it. An explicit integer or hex/decimal string is accepted too, and is
the only path when no prior breakpoint_inspect run exists yet (e.g. before
attaching at all). Nothing here ever invents a base: if none of these shapes
is supplied, live correlation is simply not attempted, and the result says
so in plain text (``live_correlation_requested: false``) rather than
guessing.
"""
from __future__ import annotations

import json

from liebert_re.workspace import safe_path, relative

TOOL_NAME = "image_address_map"

MAX_DUMP_BYTES = 256 * 1024 * 1024
DEFAULT_PREVIEW_BYTES = 32
MAX_PREVIEW_BYTES = 4096

_MACHINE_NAMES = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "ARM64"}


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _invalid_arguments(operation, error):
    return _j({
        "ok": False, "status": "INVALID_ARGUMENTS", "tool": TOOL_NAME, "operation": operation,
        "error": str(error), "execution_performed": False,
    })


# --------------------------------------------------------------------------
# Small, dependency-free integer/shape parsing. Every value that ends up in
# arithmetic below has passed through here first.
# --------------------------------------------------------------------------

def _to_int(value, label):
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer or a hex/decimal string, got a bool")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{label} must not be negative, got {value}")
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValueError(f"{label} must not be an empty string")
        try:
            n = int(s, 16) if s.lower().startswith("0x") else int(s, 10)
        except ValueError:
            raise ValueError(f"{label} is not a valid hex (0x...) or decimal integer string: {value!r}")
        if n < 0:
            raise ValueError(f"{label} must not be negative, got {n}")
        return n
    raise ValueError(f"{label} must be an integer or a hex/decimal string, got {type(value).__name__}")


def _resolve_live_base(raw, label="live_module_base"):
    """See module docstring's "Composing with guest_frida_breakpoint_inspect"
    section for the full contract. Returns ``(base_int_or_None,
    source_description_or_None)``; raises ``ValueError`` for a shape that
    carries no usable base -- this never returns a guessed value."""
    if raw is None:
        return None, None
    if isinstance(raw, bool):
        raise ValueError(f"{label} must not be a bool")
    if isinstance(raw, int):
        if raw < 0:
            raise ValueError(f"{label} must not be negative, got {raw}")
        return raw, "explicit integer"
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            raise ValueError(f"{label} must not be an empty string")
        try:
            parsed = json.loads(s)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            return _resolve_live_base(parsed, label)
        return _to_int(s, label), "explicit hex/decimal string"
    if isinstance(raw, dict):
        for key in ("live_module_base", "module_base", "base"):
            if raw.get(key) is not None:
                return _to_int(raw[key], f"{label}.{key}"), f"dict key {key!r}"
        if raw.get("address") is not None and raw.get("rva") is not None:
            address = _to_int(raw["address"], f"{label}.address")
            rva = _to_int(raw["rva"], f"{label}.rva")
            return address - rva, "derived from a resolved breakpoint record (address - rva)"
        for list_key in ("attached", "hits"):
            items = raw.get(list_key)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get("address") is not None and item.get("rva") is not None:
                        address = _to_int(item["address"], f"{label}.{list_key}[].address")
                        rva = _to_int(item["rva"], f"{label}.{list_key}[].rva")
                        return address - rva, (
                            f"derived from guest_frida_breakpoint_inspect payload's {list_key}[0] "
                            "(address - rva)"
                        )
        raise ValueError(
            f"{label} object has none of: a base/module_base/live_module_base key, an address+rva pair, "
            "or an 'attached'/'hits' list containing a resolved address+rva record -- refusing to invent a base"
        )
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("address") is not None and item.get("rva") is not None:
                address = _to_int(item["address"], f"{label}[].address")
                rva = _to_int(item["rva"], f"{label}[].rva")
                return address - rva, "derived from a list entry (address - rva)"
        raise ValueError(f"{label} list contained no entry with both 'address' and 'rva'")
    raise ValueError(f"{label} must be an int, a hex/decimal string, or an object/JSON shape, got {type(raw).__name__}")


# --------------------------------------------------------------------------
# Dump layout classification -- see module docstring point 1.
# --------------------------------------------------------------------------

def _classify_dump_layout(pe, file_size):
    opt = pe.OPTIONAL_HEADER
    file_alignment = int(opt.FileAlignment)
    section_alignment = int(opt.SectionAlignment)
    per_section = []
    matches = considered = 0
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("ascii", "replace")
        virt = int(s.VirtualAddress)
        raw = int(s.PointerToRawData)
        raw_size = int(s.SizeOfRawData)
        virt_size = max(int(s.Misc_VirtualSize), raw_size)
        raw_equals_virtual = raw == virt
        per_section.append({
            "name": name, "virtual_address": hex(virt), "virtual_size": virt_size,
            "raw_offset": hex(raw), "raw_size": raw_size,
            "raw_offset_equals_virtual_address": raw_equals_virtual,
        })
        if raw_size > 0:
            considered += 1
            if raw_equals_virtual:
                matches += 1

    file_alignment_equals_section_alignment = bool(file_alignment and file_alignment == section_alignment)

    if considered:
        ratio = matches / considered
        kind = "virtual" if ratio >= 0.5 else "raw"
        confidence = "high" if ratio in (0.0, 1.0) else "medium"
        basis = f"{matches}/{considered} on-disk sections have PointerToRawData == VirtualAddress"
    elif file_alignment_equals_section_alignment:
        kind, confidence = "virtual", "low_alignment_only"
        basis = "no section carries on-disk data; FileAlignment == SectionAlignment is the only signal available"
    else:
        kind, confidence = "raw", "low_default"
        basis = "no section carries on-disk data and FileAlignment != SectionAlignment; defaulting to raw"

    return {
        "kind": kind,
        "confidence": confidence,
        "evidence_basis": basis,
        "raw_offset_equals_virtual_address_sections": f"{matches}/{considered}" if considered else None,
        "file_alignment": file_alignment,
        "section_alignment": section_alignment,
        "file_alignment_equals_section_alignment": file_alignment_equals_section_alignment,
        "file_size": file_size,
        "size_of_image": int(opt.SizeOfImage),
        "per_section": per_section,
    }


def _section_dict(s):
    return {
        "name": s.Name.rstrip(b"\0").decode("ascii", "replace"),
        "virtual_address": hex(int(s.VirtualAddress)),
        "virtual_size": max(int(s.Misc_VirtualSize), int(s.SizeOfRawData)),
        "raw_offset": hex(int(s.PointerToRawData)),
        "raw_size": int(s.SizeOfRawData),
    }


def _locate_rva(pe, rva, layout_kind):
    """Returns ``(region, section_dict_or_None, file_offset_or_None,
    file_offset_status, detail_or_None)``. ``region`` is one of ``"header"``,
    ``"section"``, ``"unmapped"``. See module docstring points 1/3/4."""
    size_of_headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    if 0 <= rva < size_of_headers:
        return "header", None, rva, "OK", "PE header region -- file offset equals RVA in every layout"
    for s in pe.sections:
        virt = int(s.VirtualAddress)
        vsize = max(int(s.Misc_VirtualSize), int(s.SizeOfRawData))
        if virt <= rva < virt + vsize:
            sect = _section_dict(s)
            raw = int(s.PointerToRawData)
            raw_size = int(s.SizeOfRawData)
            if raw_size == 0:
                return (
                    "section", sect, None, "NO_RAW_DATA_ON_DISK",
                    f"section {sect['name']!r} has SizeOfRawData=0 -- holds no bytes on disk in this dump "
                    "(typical for a packer's decompressed/executable section that only exists at runtime); "
                    "the RVA/live-address correlation is still valid, only the file offset is not",
                )
            offset_in_section = rva - virt
            if offset_in_section >= raw_size:
                return (
                    "section", sect, None, "BEYOND_RAW_DATA_ON_DISK",
                    f"RVA falls in section {sect['name']!r}'s virtual range but past its SizeOfRawData "
                    f"({raw_size} bytes actually present on disk)",
                )
            offset = rva if layout_kind == "virtual" else raw + offset_in_section
            return "section", sect, offset, "OK", None
    return (
        "unmapped", None, None, "UNMAPPED",
        "RVA falls outside every section and the PE header region (out of range, or inside an inter-section gap)",
    )


def _file_offset_to_rva(pe, offset, layout_kind):
    """Returns ``(rva_or_None, error_or_None)``. In the "virtual" layout the
    mapping is the identity (file offset == RVA by construction of that
    layout); the candidate is still validated by the caller via
    ``_locate_rva`` afterwards, so an out-of-range offset is still refused,
    never silently accepted."""
    size_of_headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    if 0 <= offset < size_of_headers:
        return offset, None
    if layout_kind == "virtual":
        return offset, None
    for s in pe.sections:
        raw = int(s.PointerToRawData)
        raw_size = int(s.SizeOfRawData)
        virt = int(s.VirtualAddress)
        if raw_size and raw <= offset < raw + raw_size:
            return virt + (offset - raw), None
    return None, (
        "file offset does not fall within any section's on-disk raw data range (raw dump layout) or the "
        "PE header region"
    )


def _preview(data, file_offset, count):
    if file_offset is None or count <= 0:
        return None
    chunk = data[file_offset:file_offset + count]
    if not chunk:
        return None
    return {"file_offset": hex(file_offset), "byte_count": len(chunk), "hex": chunk.hex()}


# --------------------------------------------------------------------------
# The model-callable tool.
# --------------------------------------------------------------------------

def image_address_map(
    dump_path,
    rva=None,
    file_offset=None,
    live_va=None,
    live_module_base=None,
    dump_layout=None,
    preview_bytes=DEFAULT_PREVIEW_BYTES,
    cancellation_token=None,
):
    """Correlates a dumped/recovered PE (``dump_path``) with the live process
    it came from, in either direction -- see module docstring for the full
    contract. Exactly ONE of ``rva``, ``file_offset``, ``live_va`` (each an
    int or a hex ``"0x..."``/decimal string) selects the query direction:

      - ``rva`` or ``file_offset``: dump-side -> (file-side facts always;
        also -> live VA if ``live_module_base`` is supplied).
      - ``live_va``: live-side -> dump-side (section, RVA, file offset, a
        bounded raw-byte preview at that location). REQUIRES
        ``live_module_base`` -- there is no way to place a live address in
        the dump without a base, and this tool never invents one.

    ``live_module_base`` is optional for the ``rva``/``file_offset``
    directions (omitting it answers the file-side questions only, and the
    result says plainly that no live correlation was requested) and
    required for ``live_va``. It accepts an explicit int/hex/decimal value,
    OR the exact shape ``guest_frida_breakpoint_inspect``
    (``tools_frida_breakpoints.py``) already reports at runtime -- a single
    ``{"address": ..., "rva": ...}`` hit/attached record, or that tool's
    full result payload (its ``attached``/``hits`` lists are searched) --
    from which ``base = address - rva`` is derived. This module never calls
    that tool or opens any guest transport itself; it only knows how to
    read the shape that tool already produces.

    ``dump_layout`` optionally overrides the auto-detected dump layout
    (``"raw"`` or ``"virtual"``/unmapped -- see module docstring point 1);
    normally left unset so detection runs and is reported under
    ``dump_layout`` in the result (a dict, not a bare string, carrying the
    concluded ``kind`` plus the full evidence used to reach it).
    ``preview_bytes`` (default 32, capped at 4096) bounds the raw hex
    preview read at the resolved file location, when one exists.

    Never raises; returns ``{"ok": bool, "status": ..., "tool":
    "image_address_map", ...}``. ``status`` is ``INVALID_ARGUMENTS`` (bad/
    ambiguous query selection, malformed base shape, ``live_va`` without a
    base), ``PATH_REFUSED``/``NOT_FOUND`` (bad ``dump_path``), ``NOT_A_PE``,
    ``TOOL_MISSING`` (``pefile`` unavailable), ``ANALYSIS_LIMITED``
    (dump exceeds this tool's size ceiling), ``UNMAPPED_RVA``/
    ``UNMAPPED_FILE_OFFSET``/``UNMAPPED_LIVE_ADDRESS`` (address genuinely
    outside every section and the header region -- ``ok: false``, per
    module docstring point 4, NEVER a fabricated number), ``OK``, or --
    whenever ``dump_path`` carries a CLR/COR20 data directory (``pe.
    is_managed_assembly: true``) AND a live address was actually computed
    (either direction) -- ``OK_MANAGED_ASSEMBLY_LIVE_ADDRESS_UNVERIFIED``
    (``ok: true`` still, but ``managed_assembly_warning`` explains that
    base+RVA arithmetic against a managed assembly does not correspond to
    where the CLR JIT places this method's code at runtime; file-side facts
    -- section, file_offset, bytes_preview -- are unaffected and still
    returned). A caller that only reads plain ``status == "OK"`` can never
    mistake a managed-assembly live-address translation for a verified one."""
    operation = "image_address_map"

    try:
        import pefile
    except ImportError as exc:
        return _j({
            "ok": False, "tool": TOOL_NAME, "status": "TOOL_MISSING", "operation": operation,
            "required_capability": "pefile", "detail": str(exc),
        })

    selected = [k for k, v in (("rva", rva), ("file_offset", file_offset), ("live_va", live_va)) if v is not None]
    if len(selected) != 1:
        return _invalid_arguments(
            operation,
            f"exactly one of rva, file_offset, live_va must be given (not zero, not more than one) -- got {selected or 'none'}",
        )
    query_kind = selected[0]

    if dump_layout is not None and dump_layout not in ("raw", "virtual"):
        return _invalid_arguments(operation, f"dump_layout must be 'raw', 'virtual', or omitted, got {dump_layout!r}")

    try:
        preview_bytes = max(0, min(int(preview_bytes), MAX_PREVIEW_BYTES))
    except (TypeError, ValueError):
        preview_bytes = DEFAULT_PREVIEW_BYTES

    try:
        query_value = _to_int(
            rva if query_kind == "rva" else file_offset if query_kind == "file_offset" else live_va,
            query_kind,
        )
    except ValueError as exc:
        return _invalid_arguments(operation, str(exc))

    try:
        live_base, live_base_source = _resolve_live_base(live_module_base)
    except ValueError as exc:
        return _invalid_arguments(operation, str(exc))

    if query_kind == "live_va" and live_base is None:
        return _invalid_arguments(
            operation,
            "live_va was given but live_module_base was not -- refusing to invent a base; supply an explicit "
            "int/hex base, or the address+rva shape guest_frida_breakpoint_inspect already reports (a single "
            "hit/attached record, or its full result payload)",
        )

    try:
        target = safe_path(dump_path)
    except PermissionError as exc:
        return _j({"ok": False, "tool": TOOL_NAME, "status": "PATH_REFUSED", "operation": operation, "error": str(exc)})
    if not target.is_file():
        return _j({"ok": False, "tool": TOOL_NAME, "status": "NOT_FOUND", "operation": operation, "path": str(dump_path)})

    try:
        file_size = target.stat().st_size
    except OSError as exc:
        return _j({"ok": False, "tool": TOOL_NAME, "status": "NOT_FOUND", "operation": operation, "error": str(exc)})
    if file_size > MAX_DUMP_BYTES:
        return _j({
            "ok": False, "tool": TOOL_NAME, "status": "ANALYSIS_LIMITED", "operation": operation,
            "error": "DUMP_TOO_LARGE", "file_size": file_size, "maximum": MAX_DUMP_BYTES,
        })

    data = target.read_bytes()
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:  # noqa: BLE001
        return _j({
            "ok": False, "tool": TOOL_NAME, "status": "NOT_A_PE", "operation": operation,
            "path": relative(target), "detail": str(exc),
        })

    layout = _classify_dump_layout(pe, file_size)
    layout_kind = dump_layout or layout["kind"]
    reported_layout = layout if dump_layout is None else {**layout, "kind": dump_layout, "overridden_from_detected": layout["kind"]}

    machine = int(pe.FILE_HEADER.Machine)
    # Managed (.NET/CLR) detection -- same signal binary_summary (liebert_re/tools/binary.py)
    # already uses and this codebase already treats as ground truth (COM
    # Descriptor / COR20 data directory, index 14, VirtualAddress != 0):
    # https://learn.microsoft.com/windows/win32/debug/pe-format -- "the
    # 15th array entry contains the RVA and size of the CLR header". A file
    # with this set is a managed assembly; base+RVA arithmetic against it
    # answers "where does this FILE offset land in memory" honestly, but
    # that is NOT where the CLR's JIT places this method's actual machine
    # code at runtime (JIT output is heap-allocated well outside the
    # module's own mapped image, entirely unrelated to file RVAs) unless
    # this happens to be a ReadyToRun/NGen image -- which this tool has no
    # way to tell apart from an ordinary IL-only assembly from the header
    # alone. See the ``managed_assembly_warning`` field below.
    is_managed_assembly = (
        len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14
        and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0
    )
    pe_info = {
        "machine": _MACHINE_NAMES.get(machine, hex(machine)),
        "image_base": hex(int(pe.OPTIONAL_HEADER.ImageBase)),
        "size_of_image": int(pe.OPTIONAL_HEADER.SizeOfImage),
        "size_of_headers": int(pe.OPTIONAL_HEADER.SizeOfHeaders),
        "entrypoint_rva": hex(int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)),
        "section_count": len(pe.sections),
        "is_managed_assembly": is_managed_assembly,
    }
    _MANAGED_ASSEMBLY_WARNING = (
        "this PE carries a CLR/COR20 data directory (a managed .NET assembly). "
        "The live address below is pure module_base + file-RVA arithmetic -- it "
        "does NOT correspond to where the CLR JIT-compiles this method's code at "
        "runtime (JIT output lives in separate, heap-allocated memory with no "
        "relationship to file RVAs), unless this is a ReadyToRun/NGen image "
        "(which cannot be distinguished from an ordinary IL assembly by this "
        "header check alone). Treat this as a FILE-relative translation only, "
        "never as a proven live code location; file-side facts (section, "
        "file_offset, bytes_preview) above are unaffected and remain accurate."
    )

    payload = {
        "ok": True, "tool": TOOL_NAME, "operation": operation, "status": "OK",
        "dump_path": relative(target),
        "dump_layout": reported_layout,
        "pe": pe_info,
        "query_kind": query_kind,
        "execution_performed": False,
    }

    if query_kind in ("rva", "file_offset"):
        if query_kind == "file_offset":
            rva_value, offset_error = _file_offset_to_rva(pe, query_value, layout_kind)
            payload["input"] = {"file_offset": hex(query_value)}
            if rva_value is None:
                payload.update({
                    "ok": False, "status": "UNMAPPED_FILE_OFFSET", "region": "unmapped",
                    "rva": None, "file_offset": None, "error": offset_error,
                })
                return _j(payload)
        else:
            rva_value = query_value
            payload["input"] = {"rva": hex(rva_value)}

        region, section, file_off, file_off_status, file_off_detail = _locate_rva(pe, rva_value, layout_kind)
        payload["region"] = region
        payload["section"] = section
        payload["rva"] = hex(rva_value)
        payload["file_offset"] = hex(file_off) if file_off is not None else None
        payload["file_offset_status"] = file_off_status
        if file_off_detail:
            payload["file_offset_detail"] = file_off_detail

        if region == "unmapped":
            payload.update({"ok": False, "status": "UNMAPPED_RVA"})
            return _j(payload)

        payload["bytes_preview"] = _preview(data, file_off, preview_bytes)
        payload["live_correlation_requested"] = live_base is not None
        if live_base is None:
            payload["live_module_base"] = None
            payload["live_virtual_address"] = None
            payload["note"] = "no live_module_base supplied -- file-side mapping only, no live address invented"
        else:
            payload["live_module_base"] = hex(live_base)
            payload["live_module_base_source"] = live_base_source
            payload["live_virtual_address"] = hex(live_base + rva_value)
            if is_managed_assembly:
                payload["status"] = "OK_MANAGED_ASSEMBLY_LIVE_ADDRESS_UNVERIFIED"
                payload["managed_assembly_warning"] = _MANAGED_ASSEMBLY_WARNING
        return _j(payload)

    # query_kind == "live_va"
    payload["input"] = {"live_va": hex(query_value)}
    payload["live_module_base"] = hex(live_base)
    payload["live_module_base_source"] = live_base_source
    payload["live_correlation_requested"] = True

    rva_value = query_value - live_base
    if rva_value < 0:
        payload.update({
            "ok": False, "status": "UNMAPPED_LIVE_ADDRESS", "region": "unmapped", "rva": None,
            "file_offset": None,
            "error": f"live_va {hex(query_value)} is below live_module_base {hex(live_base)} (negative RVA)",
        })
        return _j(payload)

    region, section, file_off, file_off_status, file_off_detail = _locate_rva(pe, rva_value, layout_kind)
    payload["region"] = region
    payload["section"] = section
    payload["rva"] = hex(rva_value)
    payload["file_offset"] = hex(file_off) if file_off is not None else None
    payload["file_offset_status"] = file_off_status
    if file_off_detail:
        payload["file_offset_detail"] = file_off_detail

    if region == "unmapped":
        payload.update({"ok": False, "status": "UNMAPPED_LIVE_ADDRESS"})
        return _j(payload)

    payload["bytes_preview"] = _preview(data, file_off, preview_bytes)
    if is_managed_assembly:
        payload["status"] = "OK_MANAGED_ASSEMBLY_LIVE_ADDRESS_UNVERIFIED"
        payload["managed_assembly_warning"] = _MANAGED_ASSEMBLY_WARNING
    return _j(payload)
