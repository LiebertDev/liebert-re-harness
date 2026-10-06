# Run-time multi-part constant assembly with a decoy string (native console crackme class)

- Mechanism: the expected value is not stored contiguously. It is assembled at run
  time from several in-binary constants (data-section loads plus embedded immediates)
  and compared with memcmp. A plausible base64-looking string sits in the binary and
  is copied to a buffer but never compared: a decoy.
- Not the same as a value derived from input or environment: every part is in the
  binary, so the documented "run-time values are not recovered" limit is only
  partly touched.
- Lesson: a plausible string in extraction output cannot be distinguished from the
  compared value without reaching the comparison site. String extraction alone is
  not an answer for this class; it can produce a wrong one.
- Try first: reach the memcmp call and trace what fills each of its two buffers.
- Harness limit: that needs a decompiler. The package ships none (licensed IDA
  required); the Ghidra wrapper gives facts only.
- Defect class seen: an existing but unlaunchable tool must yield a named status,
  not a raw exception (WinError 225 from a quarantined binary).
