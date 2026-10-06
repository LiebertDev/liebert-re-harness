Case: crackmes.de dailycracking_by_flipflop | static secret + time-derived tail, plain compare, x86 PE | solved

Target:  Public crackme "dailycracking_by_flipflop", author flipflop, crackmes.de (author page
         URL: not recorded). Windows, C/C++, x86, difficulty 1.0, uploaded 2018-03-25.
         SHA-256 e80edf70...270e52 (17362 bytes).
Done:    Triage, then IDA decompilation of the compare function through the CLI. Nothing was
         executed, so "accepted" was never observed. No writeup, comment or solver was read by
         the analysing agents. MEASURED, confidence high on structure and format: fgets(buf, 8)
         keeps at most 7 chars; static .rdata "Crackit\0" is strncpy'd in (8) via a .data
         pointer; strftime(buf, 3, "%d") from time/localtime then overwrites offset 5 with the
         zero-padded day. Recipe: "Crack" + two-digit local day of month (7 chars, "it" is
         overwritten), compared with strcmp. Example for 2026-10-06: Crack06. Month and year
         are unused; it rolls over at local midnight. An earlier note that a static-only reader
         could not pin the time-varying part down was wrong.
Gained:  Class = static secret plus a date-derived tail, plain compare: a static string is copied
         into a fixed buffer, its tail overwritten with a value derived from the local date via
         the C runtime, then a plain compare. First step: read the one compare function,
         separate static from time-derived, and test each "cannot be known statically" claim
         against the code. The AddAtomA/FindAtomA/GetAtomNameA trio looked like protection and
         was not (inference from adjacency and provenance, not a measured xref).
Harness: 1. RESOLVED, was UNRECORDED (in neither ROADMAP nor review): data past the last
            section was invisible (65% of the file). `trailing` now answers
            TRAILING_FULLY_ATTRIBUTED (COFF symbol, string table); records not decoded.
         2. `ida xrefs_to` needs the exact decorated symbol and follows no thunks: thunk half
            RECORDED (docs/ROADMAP.md:110-116), symbol half UNRECORDED (searched: decorated, mangled).
         3. `pdata` refuses x86 honestly (X86_NO_PDATA): known limit.
         4. `pe --signature` printed a shell execution-policy error beside NotSigned. UNRECORDED
            (searched ROADMAP: signature, execution policy, shell, NotSigned).
         5. `ida --operation decompile_function` returns code in `decompiled`, not `items`.
            UNRECORDED (searched ROADMAP: no match).
         6. No operation reads bytes at a virtual address or resolves a data pointer's target; the
            .data pointer, .rdata string and date format were read by hand in Python. UNRECORDED
            (searched: read, bytes, virtual address, dataflow); now in docs/ROADMAP.md.
