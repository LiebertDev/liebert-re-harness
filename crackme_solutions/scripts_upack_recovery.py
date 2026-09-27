"""Upack (dwing) packer static recovery for WNL-T2-091 (GAP-029).

Tier2 capability remediation Phase 5 Priority 4 continuation: the goal is
not "add LZMA support" in the abstract but evidence-based recovery of the
actual protected program inside a specific historical fixture. This
module drives the *real* Upack unpacking stub bytes (traced in
`benchmarks/windows_native_ladder/results/tier2/WNL-T2-091.md`) through a
sandboxed Unicorn CPU emulator -- never the real OS process, never the
target's own execution -- to recover the genuine decompressed +
relocation-fixed-up program image, then packages that image as a
standalone, never-executed PE file so Ghidra's real CFG-aware analysis
(not naive linear disassembly) can be applied to it.

Safety: Unicorn provides pure instruction-level emulation over a
synthetic, Python-process-local memory space seeded only from the frozen
corpus file's own bytes. No real Windows API is ever resolved or called:
emulation deliberately stops at STOP_AT_RELOC (right after the
CALL/JMP-relative-displacement relocation-fixup loop completes) -- one
address before the real LoadLibraryA/GetProcAddress import-resolution
loop would begin. The recovered bytes are written to disk and are never
executed by this script or any caller; only Ghidra/Capstone static
analysis is intended to run against the reconstructed file.

Addresses below (ENTRY, STOP_AT_RELOC, header/section layout) are specific
to WNL-T2-091's exact binary (sha256
e5bbf79f084933f63b77c6aeda23e5cc7e86bc858f81a234f57a70784e6cf71f) and were
derived from real, evidenced raw-disassembly tracing, not assumed generic
Upack constants -- a different Upack-packed sample would need its own
stub trace before reusing this approach.
"""
from __future__ import annotations

import struct
from pathlib import Path

TARGET_PATH = "benchmarks/windows_native_ladder/corpus/tier2/son_crackme3_son/inner/SoN CrackMe 3.exe"

IMAGE_BASE = 0x400000
IMAGE_SIZE = 0x23000          # SizeOfImage from the real PE optional header
HEADERS_SIZE = 0x200          # SizeOfHeaders
UPACK_VA = 0x401000
UPACK_SIZE = 0x10000           # .Upack section's virtual_size (raw_size=0 on disk)
RSRC_VA = 0x411000
RSRC_FILE_OFFSET = 0x200
RSRC_RAW_SIZE = 0xA3ED

ENTRY_VA = 0x41B170            # real PE AddressOfEntryPoint (redirected into .rsrc)
STOP_AT_RELOC = 0x41B310       # right after the CALL/JMP relocation-fixup loop, BEFORE
                                # the real LoadLibraryA/GetProcAddress import loop (0x41B310+)
CANDIDATE_OEP_VA = 0x401074    # traced from the import-loop's own "test eax,eax; je 0x401074"


def emulate_upack_decompression(target_path: str = TARGET_PATH) -> bytes:
    """Runs the real Upack unpacking-stub bytes in a sandboxed Unicorn x86
    emulator far enough to (a) fully decompress the LZMA-variant payload
    and (b) apply the CALL/JMP relative-displacement relocation fixups --
    but stops one address before any real Windows API would be resolved
    or called. Returns the raw 0x10000-byte reconstructed .Upack region
    (VA 0x401000-0x411000), still containing the *program image*, not the
    import table (imports remain unresolved zero placeholders).
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP

    data = Path(target_path).read_bytes()

    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(IMAGE_BASE, IMAGE_SIZE)
    mu.mem_write(IMAGE_BASE, data[:HEADERS_SIZE])
    mu.mem_write(RSRC_VA, data[RSRC_FILE_OFFSET:RSRC_FILE_OFFSET + RSRC_RAW_SIZE])

    stack_base = 0x700000
    stack_size = 0x20000
    mu.mem_map(stack_base, stack_size)
    mu.reg_write(UC_X86_REG_ESP, stack_base + stack_size - 0x1000)
    mu.reg_write(UC_X86_REG_EBP, 0)

    mu.emu_start(ENTRY_VA, STOP_AT_RELOC, timeout=0, count=0)

    eip = mu.reg_read(__import__("unicorn.x86_const", fromlist=["UC_X86_REG_EIP"]).UC_X86_REG_EIP)
    if eip != STOP_AT_RELOC:
        raise RuntimeError(f"emulation did not reach the expected post-relocation stop point: eip=0x{eip:x}, expected 0x{STOP_AT_RELOC:x}")

    return bytes(mu.mem_read(UPACK_VA, UPACK_SIZE))


def _pe32_section_header(name: bytes, virtual_size: int, virtual_address: int,
                          raw_size: int, raw_offset: int, characteristics: int) -> bytes:
    name8 = name[:8].ljust(8, b"\x00")
    return struct.pack("<8sIIIIIIHHI", name8, virtual_size, virtual_address,
                        raw_size, raw_offset, 0, 0, 0, 0, characteristics)


def build_minimal_pe(recovered_upack: bytes, out_path: str, entry_point_va: int = CANDIDATE_OEP_VA) -> None:
    """Wraps the recovered bytes in a minimal, syntactically valid PE32 so
    Ghidra can load and statically analyze it with real function-boundary
    discovery -- naive linear Capstone disassembly desyncs after the
    first misjudged instruction length, which real callers need to avoid.
    This file is NEVER executed; it exists only for static analysis.
    """
    file_alignment = 0x200
    section_alignment = 0x1000

    def align(value, boundary):
        return (value + boundary - 1) // boundary * boundary

    num_sections = 1
    section_header_size = 40
    dos_header_size = 0x40
    pe_sig_size = 4
    coff_header_size = 20
    opt_header_size = 224  # PE32 optional header (standard 96 + 128 data dirs at 16*8)

    headers_raw_size = dos_header_size + pe_sig_size + coff_header_size + opt_header_size + num_sections * section_header_size
    headers_raw_size_aligned = align(headers_raw_size, file_alignment)

    section_va = section_alignment  # 0x1000, matches UPACK_VA - IMAGE_BASE
    section_raw_offset = headers_raw_size_aligned
    section_raw_size = align(len(recovered_upack), file_alignment)
    section_virtual_size = len(recovered_upack)

    size_of_image = align(section_va + section_virtual_size, section_alignment)

    dos_header = bytearray(dos_header_size)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, dos_header_size + pe_sig_size + coff_header_size)
    # e_lfanew above is wrong on purpose-fix: PE header starts right after this DOS stub.
    struct.pack_into("<I", dos_header, 0x3C, dos_header_size)

    pe_sig = b"PE\x00\x00"
    machine = 0x014C  # IMAGE_FILE_MACHINE_I386
    characteristics = 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE
    coff_header = struct.pack("<HHIIIHH", machine, num_sections, 0, 0, 0, opt_header_size, characteristics)

    image_base = IMAGE_BASE
    opt_header = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,          # Magic (PE32)
        9, 0,           # LinkerVersion major/minor
        section_raw_size,  # SizeOfCode
        0, 0,           # SizeOfInitializedData, SizeOfUninitializedData
        entry_point_va - image_base,  # AddressOfEntryPoint (RVA)
        section_va,     # BaseOfCode
        section_va,     # BaseOfData
        image_base,     # ImageBase
        section_alignment, file_alignment,
        4, 0,           # OS version major/minor
        0, 0,           # Image version major/minor
        4, 0,           # Subsystem version major/minor
        0,              # Win32VersionValue
        size_of_image,
        headers_raw_size_aligned,  # SizeOfHeaders
        0,              # CheckSum
        2,              # Subsystem (WINDOWS_GUI)
        0,              # DllCharacteristics
        0x100000, 0x1000,  # SizeOfStackReserve/Commit
        0x100000, 0x1000,  # SizeOfHeapReserve/Commit
        0,              # LoaderFlags
        16,             # NumberOfRvaAndSizes
    ) + b"\x00" * (16 * 8)

    section_hdr = _pe32_section_header(b".recov", section_virtual_size, section_va,
                                        section_raw_size, section_raw_offset,
                                        0xE0000020)  # READ|WRITE|EXECUTE|CODE

    headers = bytes(dos_header) + pe_sig + coff_header + opt_header + section_hdr
    headers = headers.ljust(headers_raw_size_aligned, b"\x00")

    section_data = recovered_upack.ljust(section_raw_size, b"\x00")

    Path(out_path).write_bytes(headers + section_data)


def recover_and_build(out_path: str, target_path: str = TARGET_PATH) -> dict:
    recovered = emulate_upack_decompression(target_path)
    build_minimal_pe(recovered, out_path)
    return {
        "recovered_bytes": len(recovered),
        "out_path": out_path,
        "entry_point_va": hex(CANDIDATE_OEP_VA),
        "image_base": hex(IMAGE_BASE),
    }


# ---------------------------------------------------------------------------
# Import-directory reconstruction
#
# The binding below was OBSERVED, not inferred: `emulate_binary`'s `watch_writes`
# recorded exactly 11 four-byte stores into 0x401000-0x401028, all issued by the
# same instruction (pc=0x41b33c, the GetProcAddress call site), one per
# GetProcAddress call, in order. See WNL-T2-091.md's 2026-08-27 update.
#
# Every stored VALUE was 0x0 -- speakeasy has no real MSVBVM60.DLL -- so what is
# known is slot -> NAME, never slot -> real address. That is exactly what an
# import directory encodes, which is why this reconstruction is possible at all
# without any real address ever being needed.

IAT_BASE_VA = 0x401000

# (symbol, is_ordinal). Order IS the binding: slot N = IAT_BASE_VA + 4*N.
MSVBVM60_IMPORTS: tuple[tuple[object, bool], ...] = (
    ("MethCallEngine", False),
    (0x253, True),
    (0x12F, True),
    (0x208, True),
    (0x135, True),
    ("EVENT_SINK_AddRef", False),
    ("EVENT_SINK_Release", False),
    ("EVENT_SINK_QueryInterface", False),
    ("__vbaExceptHandler", False),
    (0x2AD, True),
    (0x64, True),
)
IMPORT_DLL_NAME = b"MSVBVM60.DLL"


def build_import_directory(imports, dll_name: bytes, iat_rva: int, idata_rva: int):
    """Build the bytes of an import directory whose FirstThunk is an EXISTING
    IAT already present elsewhere in the image.

    Generic: it encodes no packer and no sample. Given a symbol list, the RVA of
    an already-located IAT, and where the new section will live, it returns
    (idata_bytes, thunk_values) -- the second being what the IAT slots must
    contain for a structurally correct *unbound* on-disk PE.

    Layout: descriptors (2 x 20) | ILT (n+1 x 4) | hint/name entries | dll name.
    """
    descriptor_size = 20 * 2
    ilt_size = (len(imports) + 1) * 4
    names_rva = idata_rva + descriptor_size + ilt_size

    name_blob = bytearray()
    thunks = []
    for symbol, is_ordinal in imports:
        if is_ordinal:
            thunks.append(0x80000000 | (int(symbol) & 0xFFFF))
            continue
        entry_rva = names_rva + len(name_blob)
        name_blob += struct.pack("<H", 0)                      # Hint
        name_blob += symbol.encode("ascii") + b"\x00"
        if len(name_blob) % 2:                                  # IMAGE_IMPORT_BY_NAME is word-aligned
            name_blob += b"\x00"
        thunks.append(entry_rva)

    dll_name_rva = names_rva + len(name_blob)
    tail = bytearray(dll_name + b"\x00")

    ilt = b"".join(struct.pack("<I", value) for value in thunks) + b"\x00\x00\x00\x00"
    descriptors = struct.pack(
        "<IIIII",
        idata_rva + descriptor_size,   # OriginalFirstThunk -> the ILT
        0, 0,                          # TimeDateStamp, ForwarderChain
        dll_name_rva,
        iat_rva,                       # FirstThunk -> the IAT already in the image
    ) + b"\x00" * 20                   # null terminator descriptor

    return bytes(descriptors + ilt + bytes(name_blob) + bytes(tail)), thunks


def build_pe_with_imports(recovered_upack: bytes, out_path: str,
                          entry_point_va: int = CANDIDATE_OEP_VA) -> dict:
    """Same minimal PE32 as `build_minimal_pe`, plus a real import directory
    pointing at the observed IAT, so a static analyzer resolves those slots by
    name instead of showing bare indirect calls through zeroed memory.

    NEVER executed. Static analysis only.

    One honest deviation from the recovered bytes, recorded because it is a
    reconstruction artefact rather than recovered data: the 44 IAT bytes at
    0x401000-0x40102b are overwritten with the canonical unbound ILT values.
    Emulation observed them as all-zero (the synthetic GetProcAddress returned
    0x0 every time), and an unbound on-disk PE carries the ILT values there, so
    this makes the file structurally correct rather than merely parseable. The
    untouched image remains available from `emulate_upack_decompression`.
    """
    file_alignment, section_alignment = 0x200, 0x1000

    def align(value, boundary):
        return (value + boundary - 1) // boundary * boundary

    num_sections = 2
    headers_raw = 0x40 + 4 + 20 + 224 + num_sections * 40
    headers_raw_aligned = align(headers_raw, file_alignment)

    recov_rva = section_alignment
    recov_raw_off = headers_raw_aligned
    recov_raw_size = align(len(recovered_upack), file_alignment)

    idata_rva = align(recov_rva + len(recovered_upack), section_alignment)
    iat_rva = IAT_BASE_VA - IMAGE_BASE

    idata_bytes, thunks = build_import_directory(
        MSVBVM60_IMPORTS, IMPORT_DLL_NAME, iat_rva, idata_rva,
    )
    idata_raw_off = recov_raw_off + recov_raw_size
    idata_raw_size = align(len(idata_bytes), file_alignment)

    image = bytearray(recovered_upack)
    iat_offset = IAT_BASE_VA - (IMAGE_BASE + recov_rva)
    for index, value in enumerate(thunks):
        struct.pack_into("<I", image, iat_offset + 4 * index, value)

    size_of_image = align(idata_rva + len(idata_bytes), section_alignment)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<HHIIIHH", 0x014C, num_sections, 0, 0, 0, 224, 0x0102)

    data_dirs = bytearray(16 * 8)
    struct.pack_into("<II", data_dirs, 1 * 8, idata_rva, len(idata_bytes))      # Import
    struct.pack_into("<II", data_dirs, 12 * 8, iat_rva, len(thunks) * 4)        # IAT

    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 9, 0, recov_raw_size, idata_raw_size, 0,
        entry_point_va - IMAGE_BASE, recov_rva, recov_rva, IMAGE_BASE,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0,
        size_of_image, headers_raw_aligned, 0, 2, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + bytes(data_dirs)

    sections = (
        _pe32_section_header(b".recov", len(recovered_upack), recov_rva,
                             recov_raw_size, recov_raw_off, 0xE0000020)
        + _pe32_section_header(b".idata", len(idata_bytes), idata_rva,
                               idata_raw_size, idata_raw_off, 0xC0000040)
    )

    headers = (bytes(dos) + b"PE\x00\x00" + coff + opt + sections).ljust(headers_raw_aligned, b"\x00")
    Path(out_path).write_bytes(
        headers
        + bytes(image).ljust(recov_raw_size, b"\x00")
        + idata_bytes.ljust(idata_raw_size, b"\x00")
    )
    return {
        "out_path": out_path,
        "imports": len(MSVBVM60_IMPORTS),
        "iat_va": hex(IAT_BASE_VA),
        "idata_rva": hex(idata_rva),
        "entry_point_va": hex(entry_point_va),
        "binding_source": "observed via emulate_binary watch_writes, WNL-T2-091.md 2026-08-27",
    }
