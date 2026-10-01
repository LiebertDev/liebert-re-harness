# Solved index

Which public crackmes this harness has a worked solution for. One line each:
name (author, corpus id), protection class, what defeated it.

The per-binary scripts are not in the working tree. They live on the
`archive/crackme-solutions` branch under `crackme_solutions/`:

    git checkout archive/crackme-solutions
    git show archive/crackme-solutions:crackme_solutions/<file>

What transfers to other binaries is in [docs/PROTECTION_CLASSES.md](docs/PROTECTION_CLASSES.md),
organized by protection class. Serials and keys are deliberately not recorded here.

Status is only as strong as the record. `VERIFIED_SOLVE` and `PARTIAL_SOLVE` are the
labels in [docs/BENCHMARKS.md](docs/BENCHMARKS.md). Where that file does not carry a
label for an entry, the line says "script only": a solution script exists on the
archive branch, but this index does not claim more than that.

| Crackme (author, id) | Protection class | What defeated it | Status |
|---|---|---|---|
| SoN CrackMe Cubed (SoN, WNL-T2-079) | VB6 P-Code, runtime-assembled serial, decoy literal | decoded the P-Code; the only writer of the compared field assembles the serial from immediates; the MD5-shaped literal sits in an unreachable region | VERIFIED_SOLVE |
| mutated crackme 5/10 (0xbabe, WNL-T2-002) | mutated control flow, MBA flag synthesis, no real `cmp` | ran the program's own check under emulation and read three gate constants rather than reimplementing | VERIFIED_SOLVE |
| SoN CrackMe 3 (son, WNL-T2-091) | Upack packer around VB6 P-Code | emulated the unpacker stub to recover the image; the serial was not derived | PARTIAL_SOLVE |
| SoN Console CrackMe 2 (WNL-T2-077) | VB6 P-Code, serial built from immediates at runtime | bounded P-Code interpreter driven by the decoder's own opcode semantics | script only |
| silnice (WNL-T2-007) | self-decrypting payload, input patches immediates, no stored serial | reimplemented the arithmetic; the sum gate is weaker than the true condition, so the payload itself is checked | script only |
| keygenme_3 (dcoder, WNL-T2-093) | additive SipHash-2-4 sum check | identified SipHash from its constants; birthday/meet-in-the-middle search with a bounded budget (probabilistic) | script only |
| knapsack_decodeme (blueowl, WNL-T2-082) | subset-sum (knapsack) cipher | Lagarias-Odlyzko lattice reduction (LLL); the "cannot brute force" claim is irrelevant | script only |
| 2nd CrackMe Advanced (bilal, WNL-T2-071) | machine-bound key, plain MD5 of a hardware id | recognised MD5 from its init and round constants; key is `md5(processor id)` | script only |
| crackMe (easlog, WNL-T2-052) | custom many-to-one 32-char hash against a constant | transcribed the hash, bound it to the target's verdict under emulation, sampled a preimage | script only |
| Find the decryption key #2 (WNL-T2-003) | custom packer, four stacked sub/xor layers over repeating 16-byte keys | reproduced all four stages; checked output by MSVC section names; decrypt only, challenge answer not recorded here | script only (decrypt stage) |
