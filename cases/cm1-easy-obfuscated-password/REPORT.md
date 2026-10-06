Case: cm1-easy-obfuscated-password (crackmes.one, author "git", 1.4/6; URL not recorded) | native PE64, dead SSE constant assembly beside live custom base64 decode, length + memcmp | solved

Target:  Public crackme by "git", native x64 PE, console password prompt. Rated easy.
Done:    Static pass with licensed IDA through the CLI. main copies the
         base64-looking string into a std::string and hands it to a hand-written,
         table-driven base64 decoder (standard alphabet) in a callee; its output
         is compared to the input by length check then memcmp. The SSE and
         immediate assembly is dead: two buffers filled, only destroyed. A valid
         input is constructible statically. An earlier pass of this case had the
         direction backwards (string called decoy, dead assembly called live).
Gained:  String extraction cannot tell a consumed input from a dead one; a
         plausible-looking constant is not evidence of being live. First step for
         this class: find the compare operand and trace backwards to what fills
         it, not forward from an interesting string. The earlier pass erred by
         reading forward. Confidence: structure high; decoder-output to input
         mapping medium-high (decompilation only).
Harness: 1. No tool says whether a string's bytes are ever consumed, or by what.
            ROADMAP records whole-program dataflow (same family); the narrower
            question, which buffers reach the compare operand: now recorded.
         2. Decompiler argument recovery is a hint: the callee's second parameter
            had no visible source in the pseudocode; only disassembly showed what
            was passed. Practice: check call-site argument registers against
            disassembly before trusting a signature. Practice, not a ROADMAP item.
         3. trailing (NO_TRAILING_DATA, file ends at last section) and pdata (63
            entries, boundaries IDA already had) were correct and added nothing.
            Correct negative and redundant confirmation are results. Nothing to record.
         4. A base64 decoder is recognisable by its table, but no shipped tool names
            it. Whether capa or FLIRT would: UNKNOWN, not run. UNRECORDED.
