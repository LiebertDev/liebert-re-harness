Case: crackmes.one "Challenge #5" by fuxy | input to bit-text, distance-zero compare, x64 PE | solved

Target:  Public crackme "Challenge #5", author fuxy, crackmes.one (original page URL: not
         recorded). Windows, C/C++, x86-64, difficulty 2.0, quality 5.0, uploaded 2026-03-19.
         SHA-256 7764a563...3065c59 (18944 bytes).
Done:    Triage, then IDA via the CLI. No packing, crypto or anti-debug. Input is turned into
         a bit-text form and compared with a stored reference; distance zero is accepted.
         Length and boundary handling around it is weak. A valid input is constructible
         statically for any run. A flag-like blob in .rdata was NOT proven decoy or reference.
Gained:  Class = transform, then distance compare against a stored reference. First step: find
         the compare, read the transform, and build the input statically. Settle each odd lead
         with a tool before theorising: the VirtualQuery/VirtualProtect pair was the MinGW
         pseudo-relocation fixer, the TLS callbacks were the MinGW tlssup pattern with no
         debugger check, .rsrc was one manifest plus padding (pe --resources, no payload).
         PARTIAL: Sleep has no caller found, only its import thunk; indirect calls through
         .rdata could not be excluded.
Harness: 1. xrefs_to on an import, IAT slot or thunk returns OK with empty items, read as "no
            callers". Was UNRECORDED; now recorded in ROADMAP (searched ROADMAP and review).
         2. decompile_function returns code under `decompiled`; `items` holds name, address and
            signature only. UNRECORDED, minor (searched ROADMAP and review).
         3. No import-caller or data-reference search; a hand-written byte scan was needed. The
            dataflow part is at ROADMAP "whole-program dataflow"; the new part is UNRECORDED
            before, now recorded.
         4. pdata gave 48 entries, table_complete true, no IDA session, and its extents
            separated the program's routines from CRT and runtime. It did not find the answer
            on a 7 KB image: triage and cross-check value only.
