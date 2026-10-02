"""Shared programmatic PE fixtures (the recipe in docs/CORPUS.md, "Fixtures for tests").

One builder for the smallest 32-bit PE that exercises a code path, so a test does not depend on a
binary the contributor has to download and a reviewer can see which field a parser test is about.

    build_pe(code)                         one executable section holding ``code``; no resource directory
    build_pe(code, resources=[...])        the same plus a ``.rsrc`` section and data directory 2
    build_pe(code, resources=[...], truncate_in_resource_data=True)
                                           the same file cut inside the first resource's data

``resources`` is a list of ``(type, name, language, data)``. ``type`` and ``name`` are an int (an ID entry)
or a str (a NAME entry, stored as the UTF-16 string the format uses); ``data`` is bytes. The tree is the
standard three levels (type -> name -> language), the data entries carry RVAs inside ``.rsrc``, and ID
entries are sorted after NAME entries as the format requires.

``build_pe(code)`` without resources is byte-for-byte what ``_build_minimal_exec_pe`` in
tests/test_disassemble_pe_skipdata.py produced before it moved here; that helper is now an alias of it.
"""
from __future__ import annotations

import hashlib
import struct

IMAGE_BASE = 0x00400000
SECTION_RVA = 0x1000
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
HEADER_SIZE = 0x200

# Well-known resource type IDs (winuser.h) used by the tests.
RT_ICON = 3
RT_RCDATA = 10
RT_MANIFEST = 24
LANG_EN_US = 0x0409

_HIGH_BIT = 0x80000000


def pseudo_random_bytes(n: int, seed: str = "liebert-pe-fixture") -> bytes:
    """``n`` deterministic, high-entropy bytes (SHA-256 in counter mode): the same on every Python
    version and every machine, unlike a Mersenne-Twister stream whose bytes depend on how they are drawn."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:n])


def _align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def _resource_section(resources, rva: int):
    """Serialise the resource tree. Returns (bytes, offset of the first data blob inside the section,
    length of that first blob). Layout: directories, data entries, name strings, then the raw data."""
    tree: dict = {}
    for rtype, name, lang, data in resources:
        tree.setdefault(rtype, {}).setdefault(name, {})[lang] = data

    def dir_size(count):
        return 16 + 8 * count

    off = dir_size(len(tree))
    root_off = 0
    type_off, name_off, entry_off = {}, {}, {}
    for t, names in tree.items():
        type_off[t] = off
        off += dir_size(len(names))
    for t, names in tree.items():
        for n, langs in names.items():
            name_off[(t, n)] = off
            off += dir_size(len(langs))
    for t, names in tree.items():
        for n, langs in names.items():
            for lang in langs:
                entry_off[(t, n, lang)] = off
                off += 16                                   # IMAGE_RESOURCE_DATA_ENTRY
    strings, string_off = bytearray(), {}
    string_base = off
    for key in {k for t, names in tree.items() for k in (t, *names)}:
        if isinstance(key, str):
            string_off[key] = string_base + len(strings)
            strings += struct.pack("<H", len(key)) + key.encode("utf-16le")
    data_base = _align(string_base + len(strings), 4)
    blobs, data_off = bytearray(), {}
    first_len = None
    for t, names in tree.items():
        for n, langs in names.items():
            for lang, data in langs.items():
                data_off[(t, n, lang)] = data_base + len(blobs)
                first_len = len(data) if first_len is None else first_len
                blobs += data + b"\0" * (-len(data) % 4)
    out = bytearray(data_base + len(blobs))

    def put_dir(at, entries):
        named = [e for e in entries if isinstance(e[0], str)]
        by_id = sorted(e for e in entries if not isinstance(e[0], str))
        struct.pack_into("<IIHHHH", out, at, 0, 0, 0, 0, len(named), len(by_id))
        at += 16
        for key, target in named + by_id:
            ident = (_HIGH_BIT | string_off[key]) if isinstance(key, str) else key
            struct.pack_into("<II", out, at, ident, target)
            at += 8

    put_dir(root_off, [(t, _HIGH_BIT | type_off[t]) for t in tree])
    for t, names in tree.items():
        put_dir(type_off[t], [(n, _HIGH_BIT | name_off[(t, n)]) for n in names])
        for n, langs in names.items():
            put_dir(name_off[(t, n)], [(lang, entry_off[(t, n, lang)]) for lang in langs])
            for lang, data in langs.items():
                struct.pack_into("<IIII", out, entry_off[(t, n, lang)], rva + data_off[(t, n, lang)], len(data), 0, 0)
    out[string_base:string_base + len(strings)] = strings
    out[data_base:] = blobs
    return bytes(out), data_base, first_len


def build_pe(code: bytes = b"\xc3", resources=None, *, truncate_in_resource_data: bool = False) -> bytes:
    """A minimal 32-bit PE: one executable ``.text`` section holding ``code`` verbatim (padded to file
    alignment), and, when ``resources`` is given, a ``.rsrc`` section whose tree is data directory 2.
    With ``truncate_in_resource_data`` the file ends halfway through the first resource's bytes: every
    header and the whole directory tree are intact, but the section header and the data entries still
    declare bytes that are no longer in the file (what a cut-off download looks like)."""
    if truncate_in_resource_data and not resources:
        raise ValueError("truncate_in_resource_data needs resources to truncate")
    text_size = max(_align(len(code), FILE_ALIGNMENT), FILE_ALIGNMENT)
    text = bytearray(text_size)
    text[:len(code)] = code

    rsrc = b""
    rsrc_rva = SECTION_RVA + _align(text_size, SECTION_ALIGNMENT)
    cut_in_rsrc = 0
    if resources:
        rsrc, data_base, first_len = _resource_section(resources, rsrc_rva)
        cut_in_rsrc = data_base + first_len // 2
        rsrc += b"\0" * (-len(rsrc) % FILE_ALIGNMENT)
    nsections = 2 if resources else 1
    image_size = (rsrc_rva + _align(len(rsrc), SECTION_ALIGNMENT)) if resources else SECTION_RVA + text_size

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)
    file_header = struct.pack("<HHIIIHH", 0x014C, nsections, 0, 0, 0, 0xE0, 0x0102)   # i386, 32-bit exe
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B, 0, 0,                       # PE32
        len(code), 0, 0,
        SECTION_RVA,                        # entry point (the code is never run)
        SECTION_RVA, 0,
        IMAGE_BASE,
        SECTION_ALIGNMENT, FILE_ALIGNMENT,
        4, 0, 0, 0, 4, 0,                   # versions
        0,                                  # win32 version
        image_size,
        HEADER_SIZE,
        0,                                  # checksum
        3, 0,                               # subsystem CONSOLE, dll characteristics
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16)                              # loader flags, number of data directories
    directories = bytearray(16 * 8)         # all zero unless a resource tree is attached
    if resources:
        struct.pack_into("<II", directories, 2 * 8, rsrc_rva, len(rsrc))     # IMAGE_DIRECTORY_ENTRY_RESOURCE
    sections = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", text_size, SECTION_RVA, text_size,
                           HEADER_SIZE, 0, 0, 0, 0, 0x60000020)              # code, executable, readable
    if resources:
        sections += struct.pack("<8sIIIIIIHHI", b".rsrc\x00\x00\x00", len(rsrc), rsrc_rva, len(rsrc),
                                HEADER_SIZE + text_size, 0, 0, 0, 0, 0x40000040)   # initialised data, readable

    headers = bytearray(HEADER_SIZE)
    headers[0:0x40] = dos
    at = 0x40
    headers[at:at + 4] = b"PE\x00\x00"
    at += 4
    for blob in (file_header, optional, bytes(directories), sections):
        headers[at:at + len(blob)] = blob
        at += len(blob)
    pe = bytes(headers) + bytes(text) + rsrc
    if truncate_in_resource_data:
        pe = pe[:HEADER_SIZE + text_size + cut_in_rsrc]
    return pe
