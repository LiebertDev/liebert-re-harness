# Crackme solutions

Standalone attack and analysis scripts written while working the challenge corpus
in [../docs/BENCHMARKS.md](../docs/BENCHMARKS.md). They are here because they read
well on their own: each one is a small, complete answer to a specific question
about a specific binary, which is a better introduction to this toolkit than any
tutorial.

**The challenge binaries are not included.** Each script's docstring names the
challenge and its author; [../docs/CORPUS.md](../docs/CORPUS.md) explains how to
fetch the same file and verify you have the right one. Where a challenge author set
rules — keygen only, no patching — the solution respects them, because otherwise it
is not a solution to that challenge.

## What runs, and what does not

Stated up front rather than left for you to discover, since one of these has a
real dependency gap in this packaging:

| Script | Status |
|---|---|
| `scripts_keygenme3_siphash_attack.py` | Self-contained |
| `scripts_keygenme3_mitm.py` | Self-contained |
| `scripts_knapsack_lll_attack.py` | Self-contained |
| `scripts_2nd_crackme_advanced_keygen.py` | Self-contained |
| `scripts_easlog_keygen_wnl052.py` | Self-contained |
| `scripts_silnice_unlock.py` | Self-contained |
| `scripts_son_cubed_serial.py` | Self-contained |
| `scripts_vb6_pcode_interpret.py` | Runs; uses `tools_vb6_pcode` from this repo |
| `scripts_upack_recovery.py` | Runs; uses this repo's modules |
| `scripts_find_decryption_key2_unpack.py` | Runs; uses this repo's modules |
| `scripts_mutated_crackme5_serial.py` | **Documentation only — will not run here.** Its `run()` imports `tools_emulate_range`, which is part of the upstream tree and is not shipped in this package. The reasoning and the recovered algorithm are the value; the entry point is not executable as-is. |

`tools_vb6_pcode.py`'s `operation="program_strings"` path was previously
believed to import a module not shipped here; verified false — it only imports
`pefile` and `capstone`, both shipped dependencies, and runs. The one real gap
above (`scripts_mutated_crackme5_serial.py`) is listed rather than patched
over, because a script that half-runs and reports a plausible wrong answer
would be worse than one that fails loudly — see the one rule in
[../CONTRIBUTING.md](../CONTRIBUTING.md).

Closing that gap is a good first contribution.

## Highlights

- **`scripts_knapsack_lll_attack.py`** — Lagarias–Odlyzko attack on a subset-sum
  (knapsack) key check, via LLL lattice reduction. The interesting part is that
  the challenge's "impossible to brute force" claim is true and irrelevant: the
  problem is not a search.
- **`scripts_keygenme3_siphash_attack.py`** — key recovery against a SipHash-based
  check, with the key schedule reimplemented rather than lifted.
- **`scripts_keygenme3_mitm.py`** — meet-in-the-middle search where the state space
  splits cleanly in half.
- **`scripts_vb6_pcode_interpret.py`** — a VB6 P-Code interpreter. Several corpus
  entries hide their serial as immediates assembled at runtime inside P-Code, where
  no string search will ever find it. One of them also ships a decoy MD5-shaped
  string in the literal table that is never reached.
- **`scripts_upack_recovery.py`** — emulation-assisted unpacking of a packed VB6
  binary (section entropy 7.476 → 5.754, 99.1% bytecode coverage). Worth reading
  alongside the note in `docs/BENCHMARKS.md` that this challenge is still recorded
  as `PARTIAL_SOLVE`: unpacking it was not the same as solving it.
