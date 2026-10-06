Case: cm1-easy-obfuscated-password (crackmes.one, author "git", 1.4/6; URL not recorded) | native PE64, dead SSE constant assembly beside live custom base64 decode, length + memcmp | solved

Target:  Public crackme by "git", native x64 PE, console password prompt. Rated easy.
Done:    Static pass with licensed IDA through the CLI. Nothing was executed. EXPOSURE: the intake
         agent read the target page's writeups before analysis and was excluded from analysing
         it; the analysis was done by separate agents that read no writeup, comment or solver.
         MEASURED answer: TotallyNotThePassword (21 chars). main copies the base64-looking string
         into a std::string and hands it to a hand-written table-driven decoder; its output is
         compared by a length check then memcmp. The callee's 256-entry table was read out: the
         standard alphabet, no deviation in any of the 64 assigned positions, unassigned bytes
         -1 (fill constant's raw bytes checked). A standard decode and one using a table built
         only from the callee's own assignments gave the same 21 bytes. The length check needs
         exactly 21, so unlike fuxy there is no short or empty input bypass. The SSE and
         immediate assembly is dead: two buffers filled, only destroyed. An earlier pass had
         the direction backwards (string called decoy, dead assembly called live).
Gained:  String extraction cannot tell a consumed input from a dead one; a plausible-looking
         constant is not evidence of being live. First step for this class: find the compare
         operand and trace backwards to what fills it, not forward from an interesting string.
         The earlier pass erred by reading forward. Confidence: high (decompilation plus raw-byte reads).
Harness: 1. No tool says whether a string's bytes are ever consumed, or by what. ROADMAP records
            whole-program dataflow (same family); the narrower question, which buffers reach
            the compare operand: now recorded.
         2. Decompiler argument recovery is a hint: a callee parameter had no source in the
            pseudocode; only disassembly showed it. Check call-site registers. Practice only.
         3. trailing and pdata (63 entries) were correct, added nothing. No record.
         4. A base64 decoder is recognisable by its table, but no shipped tool names it. Whether
            capa or FLIRT would: UNKNOWN, not run. UNRECORDED.
         5. No operation reads bytes at a virtual address or resolves a data pointer's target;
            the .data pointer, .rdata string, fill constant and decode were done by hand in
            Python. Three targets. UNRECORDED (searched ROADMAP: read, bytes, virtual address,
            dataflow); nearest entry is the opposite direction. Now recorded.
         6. `ida` with a relative path plus `--workspace` gave PATH_REFUSED / FILE_NOT_FOUND; an
            absolute path worked. UNRECORDED (searched ROADMAP: relative, absolute, workspace).
