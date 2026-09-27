"""WNL-T2-003 -- reproduce the four-stage decrypt in "Find the decryption key #2".

The target (`agesa113377.exe`, a custom-packed x86-64 binary) decrypts 4,932 bytes
at `0x14004a5bb` before running them. The decrypt is not one transform but **four**,
each a counted loop over a repeating 16-byte key, alternating subtraction and
exclusive-or:

| stage | loop head | writing instruction | operation | key |
| --- | --- | --- | --- | --- |
| 1 | `0x1400481a3` | `0x1400481a7` | `sub byte ptr [rax], r9b` | `0x14004a57b` |
| 2 | `0x140048bab` | `0x140048baf` | `xor byte ptr [rax], r9b` | `0x14004a58b` |
| 3 | `0x140049368` | `0x14004936c` | `sub byte ptr [rax], r9b` | `0x14004a59b` |
| 4 | `0x140049ec6` | `0x140049eca` | `xor byte ptr [rax], r9b` | `0x14004a5ab` |

The four keys are consecutive 16-byte blocks. Each loop runs
`inc rax; inc r8; and r8, 0xf; dec edx; jne <head>` with `edx = 4932`, so every stage
covers the whole region.

Applying all four in order produces MSVC image data: a table of little-endian dword
triples with the shape of a `.pdata` runtime-function table, followed by the section
names `.pdata`, `.rdata`, `.rdata$voltmd`, `.rdata$zzzdbg`, `.text$mn` and `.xdata`.

**The target is read out of its archive in memory and never written to disk.**
Extracting it produces a file the host's antivirus removes within a minute, which is
an artefact of a packed crackme matching a signature rather than anything about the
repository. Nothing here executes it: the stage parameters above were recovered once
by emulation and are constants now, and this module only reads bytes.
"""
from __future__ import annotations

import os
import zipfile

ARCHIVE = os.path.join(
    "benchmarks", "windows_native_ladder", "corpus", "tier2", "find_decryption_key2.zip",
)
MEMBER = "agesa113377.exe"
PASSWORD = b"crackmes.one"

IMAGE_BASE = 0x140000000
DESTINATION = 0x14004A5BB
LENGTH = 4932
KEY_SIZE = 16

# (key virtual address, operation), in the order the unpacker applies them.
STAGES = (
    (0x14004A57B, "sub"),
    (0x14004A58B, "xor"),
    (0x14004A59B, "sub"),
    (0x14004A5AB, "xor"),
)

# Section names MSVC emits, which the decrypted region carries. Used as the
# recognisability check rather than a hash, because the point is that the output is
# real image data.
EXPECTED_SECTION_NAMES = (
    b".pdata", b".rdata", b".rdata$voltmd", b".rdata$zzzdbg", b".text$mn", b".xdata",
)


def read_target(archive: str = ARCHIVE) -> bytes:
    """The packed binary's bytes, straight from the archive."""
    with zipfile.ZipFile(archive) as bundle:
        return bundle.read(MEMBER, pwd=PASSWORD)


def mapped_image(target: bytes):
    """The target mapped as it would be in memory, with its image base."""
    import pefile

    binary = pefile.PE(data=target)
    return binary.OPTIONAL_HEADER.ImageBase, binary.get_memory_mapped_image()


def stage_keys(image: bytes, base: int = IMAGE_BASE) -> tuple[bytes, ...]:
    """The four 16-byte keys, read from the image at the recorded addresses."""
    return tuple(image[va - base:va - base + KEY_SIZE] for va, _ in STAGES)


def apply_stage(buffer: bytes, key: bytes, operation: str) -> bytes:
    """One loop: a repeating key applied byte by byte over the whole region."""
    if operation not in ("sub", "xor"):
        raise ValueError("unknown operation %r" % operation)
    out = bytearray(len(buffer))
    for index, value in enumerate(buffer):
        k = key[index % len(key)]
        out[index] = (value - k) & 0xFF if operation == "sub" else value ^ k
    return bytes(out)


def decrypt(image: bytes, base: int = IMAGE_BASE) -> bytes:
    """Run all four stages over the encrypted region and return the plaintext."""
    buffer = image[DESTINATION - base:DESTINATION - base + LENGTH]
    if len(buffer) != LENGTH:
        raise ValueError("the encrypted region is not %d bytes in this image" % LENGTH)
    for (key_va, operation), key in zip(STAGES, stage_keys(image, base)):
        buffer = apply_stage(buffer, key, operation)
    return buffer


def looks_like_image_data(plain: bytes) -> bool:
    """Whether the plaintext carries the MSVC section names it should."""
    return all(name in plain for name in EXPECTED_SECTION_NAMES)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--archive", default=ARCHIVE)
    parser.add_argument("--out", help="write the decrypted region to this path")
    arguments = parser.parse_args(argv)

    base, image = mapped_image(read_target(arguments.archive))
    plain = decrypt(image, base)
    print("decrypted %d bytes from %s" % (len(plain), hex(DESTINATION)))
    print("recognisable image data:", looks_like_image_data(plain))
    for name in EXPECTED_SECTION_NAMES:
        if name in plain:
            print("   %-16s at offset %d" % (name.decode(), plain.index(name)))
    if arguments.out:
        with open(arguments.out, "wb") as handle:
            handle.write(plain)
        print("written to", arguments.out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
