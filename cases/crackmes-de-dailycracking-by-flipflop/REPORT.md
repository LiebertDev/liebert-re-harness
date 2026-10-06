Case: crackmes.de dailycracking_by_flipflop | static secret + time-derived tail, plain compare, x86 PE | solved

Target:  Public crackme "dailycracking_by_flipflop", author flipflop, via crackmes.de
         (author page URL: not recorded). Windows, C/C++, x86, difficulty 1.0, uploaded
         2018-03-25. SHA-256 e80edf70...270e52 (17362 bytes).
Done:    Triage, then IDA decompilation of the one compare function. The expected value
         depends on the local calendar date and on nothing else (no per-run or
         per-machine value, no input-dependent state), so a valid input was resolved
         statically for any date. Backed by five self-checks of what was loaded, written
         and referenced, plus the binary's own structure. An earlier note that a
         static-only reader could not pin the time-varying part down was wrong.
Gained:  Class = static secret plus a date-derived tail, plain compare: a static string
         is copied into a fixed buffer, its tail is overwritten with a value derived
         from the local date via the C runtime, then a plain compare. First step: read
         the one compare function, separate static from time-derived, and test each
         claim of "cannot be known statically" against the code before accepting it.
         The AddAtomA/FindAtomA/GetAtomNameA trio looked like protection and was not
         (inference from adjacency and provenance, not a measured xref): check for a
         compiler-runtime owner before theorising.
Harness: 1. RESOLVED, was UNRECORDED: data past the last section was invisible (65% of
            the file). `trailing` now answers TRAILING_FULLY_ATTRIBUTED as a COFF symbol
            and string table, consistent, and explicitly does not decode the records.
            Both facts stand: the gap was missing from ROADMAP and review, and this case
            caused the tool.
         2. `ida --operation xrefs_to` needs the exact decorated symbol and does not
            follow thunks. Recorded: unchecked.
         3. `pdata` refuses x86 honestly (X86_NO_PDATA). Known shape of the limit.
         4. `pe --signature` printed a shell execution-policy error beside NotSigned.
            Recorded: unchecked.
         5. UNRECORDED: no shipped operation dereferences a static data pointer; a
            throwaway script reading raw bytes was needed. Searched ROADMAP: no match.
         6. UNRECORDED: `ida --operation decompile_function` returns code in a
            `decompiled` field while `items` holds only name and address; cost a step.
            Searched ROADMAP: no match.
