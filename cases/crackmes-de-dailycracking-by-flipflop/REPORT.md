Case: crackmes.de dailycracking_by_flipflop | static secret + time-derived tail, plain compare, x86 PE | active

Target:  Public crackme "dailycracking_by_flipflop", author flipflop, via crackmes.de
         (author page URL: not recorded). Windows, C/C++, x86, difficulty 1.0, uploaded
         2018-03-25. SHA-256 e80edf70...270e52 (17362 bytes).
Done:    Measured where the harness stops helping, not defeat. Triage and IDA decompilation
         of the one compare function; the compared global was deliberately never read.
Gained:  Class = static secret plus a date-derived tail, plain compare: input read, static
         global copied to a buffer, tail overwritten, plain string compare. First step:
         read the one compare function, separate static from time-derived. The
         AddAtomA/FindAtomA/GetAtomNameA trio looked like protection and was not
         (inference from adjacency and provenance, GCC w32-shared-ptr.c, SJLJ unwinding;
         not a measured xref): check for a compiler-runtime owner before theorising.
Harness: 1. UNRECORDED: trailing data past the last section is invisible: 11218 of 17362
            bytes (65%) follow it. Only `rzbin --headers` showed PointerToSymbolTable and
            NumberOfSymbols; nothing joins them to the file tail. Consistent with an
            unstripped COFF symbol and string table (inference, not parsed); so the
            harness cannot explain IDA's named functions. Searched ROADMAP and review for
            overlay, trailing, appended, COFF, symbol table: no match. Fix in progress in
            a separate change, not done.
         2. `ida --operation xrefs_to` needs the exact decorated symbol (else
            SYMBOL_NOT_FOUND) and does not follow thunks. Usability. Recorded: unchecked.
         3. `pdata` refuses x86 honestly (X86_NO_PDATA); no x86 extent tool, IDA covered it.
            Known shape of the limit, not a defect.
         4. `pe --signature` printed a PowerShell execution-policy error beside NotSigned:
            environment noise in a result. Recorded: unchecked.
