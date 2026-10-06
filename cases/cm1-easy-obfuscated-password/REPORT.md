Case: cm1-easy-obfuscated-password (crackmes.one, author "git", 1.4/6; URL not recorded) | native PE64, run-time multi-part constant assembly + decoy string, memcmp | open (not closed)

Target:  Public crackme by "git", native x64 PE, console password prompt. Rated easy.
Done:    Ran identify, probe, pe, pdata, ida, ghidra facts and capa. probe extracted a
         plausible base64-looking string; decompilation showed it is a decoy, copied
         and never compared. The real value is assembled at run time from in-binary
         constants and compared with memcmp over different buffers.
Gained:  Class: run-time multi-part constant assembly plus a decoy, compared with
         memcmp. A plausible extracted string cannot be told from the compared
         value without reaching the comparison, so string extraction alone fails.
         Not shown: that the chain is complete. The "run-time values are not
         recovered" limit is only partly touched (parts are in-binary, not input).
Harness: 1. The step that exposed the decoy (ida decompile_function) needs a licensed
            IDA Pro; the package ships no decompiler and its Ghidra wrapper gives facts
            only. Without a licence it would hand the operator the decoy, no warning.
            Recorded in ROADMAP or review: unchecked.
         2. Defect: an existing but unlaunchable executable (capa, OS-quarantined, raw
            WinError 225) escapes bounded_subprocess's Popen as a raw exception, not a
            named status. Shared runner; fixed in a separate change. Recorded: unchecked.
