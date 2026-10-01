# What transfers: protection classes

Distilled from ten worked crackmes (listed in [../SOLVED_INDEX.md](../SOLVED_INDEX.md);
raw scripts on the `archive/crackme-solutions` branch). Organized by protection
class. Per-binary addresses, keys and serials are deliberately left out; if a line
would not help on a different binary with the same protection, it is not here.

Each class: how to recognize it, what defeats it, what to try first, what wasted time.

## Cross-cutting rule

A reimplementation is only a claim until it agrees with the target. Bind it to the
program's own verdict (emulate the check, or compare against published test vectors)
and show that a deliberately wrong input is rejected. Several of these checks looked
solved at the reading stage and were not.

## 1. VB6 P-Code

- **Recognize:** no application x86; a decoder produces opcode listings with runtime
  helper names (`rtc*`, `__vba*`). The strings you need are absent from every string table.
- **Defeats it:** decode the procedures, find the one place that writes the field the
  check reads, and read the value out of the bytecode (serials are assembled one
  character at a time from immediates). For stubborn cases, a small interpreter whose
  opcode meanings come from the decoder's output, never a hand-kept table.
- **Try first:** list every store to the compared member across all procedures. Then
  check reachability of any literal you find: compute which branch targets exist.
- **Wasted time:** string search. Trusting an MD5-shaped literal that looks like the
  answer; it was behind an always-taken branch (a string compared with itself plus a
  character can never be equal) and was a trap.
- **Interpreter facts:** an `rtc*` helper's first argument is its result, passed by
  reference, with the sources below it in reverse source order; the call operand is a
  byte count, so divide by 4. Opcode names inferred from a handler prefix can be
  ambiguous; halt on those rather than guess.

## 2. Mutated control flow (opaque predicates, MBA flags, API by arithmetic)

- **Recognize:** hundreds of `mov; or r,1; jne` predicates, API addresses computed from
  constants, and decompilers and deobfuscators reporting no comparisons at all (the
  flags are synthesized bit by bit and fed through `sahf`).
- **Defeats it:** do not reimplement from the listing. Emulate the check function in a
  sandbox with a synthetic console, feed candidates, and read what it prints. Recover
  the gate constants at the addresses that branch on them.
- **Try first:** locate the prompt and read strings, then emulate from the check entry.
  Stack-variable descriptors left by the compiler's runtime checks name the locals and
  give the input layout without a decompiler.
- **Wasted time:** looking for the comparison; there is none in the instruction stream.

## 3. Packers and layered decryption stubs

- **Recognize:** high section entropy, raw size zero with large virtual size, entry
  point redirected into a resource section (Upack); or a counted byte loop over a
  repeating 16-byte key, stacked in several stages that alternate `sub` and `xor`.
- **Defeats it:** emulate the real stub from its own bytes, stopping before imports
  resolve (after relocation fixups, before `LoadLibrary`/`GetProcAddress`), then
  rebuild a never-executed PE for static analysis. For stacked loops, take each
  stage's loop head, writing instruction and key address, and apply them in order.
- **Check the output** by something recognisable (compiler section names, a plausible
  `.pdata` table), not by a hash you do not have.
- **Wasted time:** treating unpacking as solving. A packed VB6 target unpacked to 99%
  bytecode coverage and was still only a partial solve. Also: extracting a packed
  sample to disk gets it deleted by antivirus within a minute; read it in memory.
- **Not transferable:** stub addresses and parameters. A different sample of the same
  packer needs its own stub trace.

## 4. Self-decrypting payload, input as the key

- **Recognize:** no comparison against a stored serial; a writable, executable,
  encrypted section; input characters patch immediates of arithmetic blocks whose
  results key a stream cipher; a checksum of the decrypted bytes is folded into a
  computed call target.
- **Defeats it:** reimplement the arithmetic exactly, run it per candidate, and accept
  only if the program's gate passes AND the decrypted payload is the program's own
  success code (check for a known string from it).
- **Wasted time:** accepting on the gate alone. It is far weaker than the real
  condition: about one random code in 400,000 passes the sum and almost all decrypt to
  garbage. A wrong code does not print failure, it jumps into unmapped memory, so
  "no failure message" is not evidence of success.

## 5. Standard primitives hiding in custom wrappers (MD5, SipHash, others)

- **Recognize:** initial-state words, round constants (the 64 sine-derived MD5 constants;
  the SipHash initialization string XORed out of immediates), finalization shape.
- **Defeats it:** name the primitive from its constants, reimplement, and validate
  against the primitive's published reference vectors, which are independent of the
  target. Check how the wrapper feeds it (per-character bytes, hex formatting with
  zero padding, lowercase).
- **Try first:** search the binary for the constants before reading any code.
- **Wasted time:** assuming key material is the visible ASCII string. Read the full raw
  key width from the binary; bytes past the terminator are part of it (zero padding
  here, but confirm).
- **Machine-bound keys:** if the key is a function of a hardware id read at runtime,
  the keygen is a function with that id as an explicit input; do not read hardware.

## 6. Additive or sum-of-contributions checks

- **Recognize:** a per-position precomputable value, summed mod 2^64, compared to a
  target derived from the name.
- **Defeats it:** birthday-bound or meet-in-the-middle, not enumeration. When the
  split still needs 2^64 entries, accept a probabilistic search with an explicit time
  and attempt budget that fails loudly rather than truncating.
- **Try first:** profile before computing. Vectorise the primitive (about 20x here), and
  measure the table lookup at real size: `numpy.searchsorted` ran at roughly 4e5
  queries per second on a 200M array against roughly 7e7 for a hash-bucketed direct
  index. The "obvious" lookup was the bottleneck by two orders of magnitude.

## 7. Math-structured checks (subset sum / knapsack)

- **Recognize:** a public weight list and a ciphertext that is a sum of selected
  weights; a claim that brute force is impossible.
- **Defeats it:** low-density subset-sum via LLL lattice reduction. The claim is true
  and beside the point; it is not a search problem. Try several lattice scale factors.
- **Wasted time:** blaming the attack when the parse is wrong. If exhaustive enumeration
  proves no vector of the required norm exists at several scales, the weight or target
  decoding is wrong (word order, endianness, bit order). Re-derive it from the author's
  encoder source or disassembly instruction by instruction rather than re-tuning the
  lattice. Here the bug was three 32-bit dwords arranged high-to-low in reverse file
  order, not one 96-bit little-endian integer.

## 8. Many-to-one custom hash against a constant

- **Recognize:** fixed-length alphanumeric output compared to a `.rdata` constant, with
  a normalisation loop that maps every value into an alphabet.
- **Defeats it:** the normalisation makes the hash many-to-one, so a preimage is cheap.
  Transcribe the hash, collapse the normaliser loop to a closed form, and run a
  wall-clock-bounded random sampler (not an enumeration).
- **Check:** bind the transcribed hash to the target's own verdict under emulation.
- **Edge:** very short inputs can make the target read out of bounds; handle them
  explicitly instead of trusting the transcription there.
- **Wasted time:** a record saying the program reads no input. Look for the standard
  library input call inside the function whose return value is printed.
