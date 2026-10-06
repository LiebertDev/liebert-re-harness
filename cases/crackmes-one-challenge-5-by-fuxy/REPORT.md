Case: crackmes.one "Challenge #5" by fuxy | input to bit-text, distance-zero compare, x64 PE | solved

Target:  Public crackme "Challenge #5", author fuxy, crackmes.one (original page URL: not
         recorded). Windows, C/C++, x86-64, difficulty 2.0, quality 5.0, uploaded 2026-03-19.
         SHA-256 7764a563...3065c59 (18944 bytes).
Done:    Triage, then IDA via the CLI. Nothing was executed; no writeup, comment or solver was
         read by the analysing agents. No packing, crypto or anti-debug. MEASURED answer:
         CTF{ASCII-mOre-like_BINASCII!!!}. The reference is the .rdata blob reached through a
         .data pointer; xrefs_to shows three reads, all in the comparison function, so the blob
         is the reference, not a decoy (this settles the earlier open question). The transform
         writes each input char as 8 ASCII bits, MSB first, space-separated; the compare sums
         per-bit XOR (a Hamming distance), skips spaces, accepts distance zero. Two logic
         weaknesses, MEASURED from code: the encoder loop bound never encodes the last input
         char, so the trailing "}" is never compared and any 32nd char passes; the compare
         stops at whichever string ends first, so a one-char input or bare Enter should also
         pass (INFERRED from code, not run). The fgets into a larger buffer is memory-safe.
Gained:  Class = transform, then distance compare against a stored reference. First step: find
         the compare, read the transform, and build the input statically. Settle each odd lead
         with a tool before theorising: the VirtualQuery/VirtualProtect pair was the MinGW
         pseudo-relocation fixer, the TLS callbacks were the MinGW tlssup pattern with no
         debugger check, .rsrc was one manifest plus padding (pe --resources, no payload).
         PARTIAL: Sleep has no caller found, only its import thunk; indirect calls through
         .rdata could not be excluded.
Harness: 1. xrefs_to on an import, IAT slot or thunk returns OK with empty items, read as "no
            callers". Was UNRECORDED; now in ROADMAP (searched ROADMAP and review).
         2. decompile_function returns code under `decompiled`, not `items`. UNRECORDED (searched).
         3. No import-caller or data-reference search; a byte scan was needed. Dataflow part:
            ROADMAP "whole-program dataflow"; the rest is now recorded (docs/ROADMAP.md:117).
         4. pdata (48 entries, no IDA session) separated program routines from CRT: triage only.
         5. No operation reads bytes at a virtual address or resolves a data pointer's target;
            the .data pointer, the .rdata blob and the bit-text decode were done by hand in
            Python. Three targets. UNRECORDED (searched ROADMAP: read, bytes, virtual address,
            dataflow); nearest entry is the opposite direction. Now recorded.
