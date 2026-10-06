# Dead constant-assembly distractor beside a live custom base64 decode (native console crackme class)

- Mechanism: the binary holds a base64-looking string. `main` copies it into a
  `std::string` and passes it to a hand-written, table-driven base64 decoder
  (standard alphabet, 256-entry table built in the callee). The decoder's output
  is the expected value, compared with the user's input by length check, then
  `memcmp`. Beside it sits a distractor: two more `std::string` buffers filled
  by SSE loads and immediates and only destroyed afterwards, never read.
- The distractor ran opposite to how an earlier pass of this case read it. That
  pass called the base64-looking string a decoy and the SSE assembly the real
  value. The dead value was read as live and the live input as a decoy. That
  first record was wrong and has been replaced.
- Lesson: string extraction cannot tell a consumed input from a dead one, and a
  plausible-looking constant is not evidence of being live.
- Try first: find the compare operand and trace backwards to what fills it,
  not forward from an interesting-looking string. Then confirm which buffer a
  callee actually receives from the call-site argument registers in the
  disassembly; the decompiler's recovered signature is a hint, not a fact.
- Confidence: structure high. The exact mapping from decoder output to the
  user-input bytes rests on decompilation only: medium-high.
- Solved statically: a valid input is constructible without running the target.
- Recognition: a base64 decoder is recognisable by its table. No shipped tool
  names it; whether `capa` or FLIRT would is UNKNOWN and was not run.
