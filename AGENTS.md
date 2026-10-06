# Operating rules

Python package `liebert_re/` (static reverse-engineering analysis). Setup and
tests: `pip install -e ".[dev,lattice]"`, then `pytest -q`. CLI: `python -m liebert_re --help`.
Contribution rules, including "never return a confidently wrong answer", are in
`CONTRIBUTING.md`; this file does not repeat them. Case handling is in `CASE_POLICY.md`.

Each rule names how it is checked. A rule with no machine check is stated as a duty.

## Repository

1. **Code lives in `liebert_re/`; every module has a test.** No `.py` at the repo
   root. A new module ships with a `tests/test_*.py` that references it, and the
   hard-coded module count in the `package` job of `.github/workflows/ci.yml` is
   updated in the same commit. Checked by `tests/test_repo_discipline.py`
   (`test_layout_matches_packaging`, `test_every_module_is_referenced_by_a_test`) and CI.
2. **Done means green.** `pytest -q` and `ruff check .` both pass before a commit.
   Never add an entry to a `KNOWN_*` table in `tests/test_repo_discipline.py`;
   entries may only be removed. Checked by `test_allowlists_have_not_grown`.
3. **No binaries, no analysis output in git.** Samples go in `samples/` or
   `corpus/`; tool output goes in `out/`, `output/`, `artifacts/`, `runs/` or the
   harness's own `dataset/`. All are gitignored; do not force-add. Fixtures are
   built in code and samples are cited by SHA-256 (`docs/CORPUS.md`). Checked by the
   `no-binaries` CI job and `test_no_tracked_build_or_runtime_artifacts`.
4. **Unknown stays unknown.** A function that cannot determine a value returns
   `None`, `"UNKNOWN"` or an error, never a guess; a fallback path says it was
   taken (`CONTRIBUTING.md`, first section). Checked by review and by the tests
   the change must ship with.

## Cases

Full text and the report template: `CASE_POLICY.md`.

5. **Record the class, not the binary.** What a solved case leaves behind is what
   was learned about the protection class: how it works, what defeats it, what to
   try first next time. Addresses, offsets, serials and one-binary walkthroughs are
   not knowledge to keep. The harness is not specialised for any target. Checked
   by review of the report against the template.
6. **Lifecycle: `active`, `solved`, `abandoned`.** Do not move, edit or clean the
   artifacts of an `active` case. When a case becomes `solved` or `abandoned`, its
   artifacts are purged by the purge mechanism; only generalized knowledge and the
   short report survive. Do not copy artifacts elsewhere to keep them.
7. **Close with a short report.** Exactly three answers: which target (redacted),
   what was done, what was gained for future targets. Template in `CASE_POLICY.md`.
8. **Commercial or live applications are never named.** Use `TARGET-NN` plus a
   technical category tag. Public crackmes and CTF binaries may be named. Applies
   to code, comments, tests, docs, reports and commit messages. Checked by review.
9. **Nothing identifying the operator or machine is committed.** No real
   usernames, absolute home paths, hostnames, machine identifiers, licence keys,
   credentials or tokens, including inside pasted IDA, Ghidra or debugger output.
   Substitute `<USER>`, `<HOME>`, `<HOST>`, `<MACHINE-ID>`, `<LICENCE-KEY>`,
   `<REDACTED>` (table in `CASE_POLICY.md`). Path leaks are checked by
   `test_no_machine_specific_user_paths`; the other categories are a duty and
   are not machine-checked.
10. **Stay inside `DISCLAIMER.md`'s "Out of scope" section.** No ready-to-use
    circumvention of a real, currently distributed product, and no findings about a
    third party's protection that the vendor has not disclosed. Checked by review.

## Kernel-level work

11. **Never disable, or instruct the operator to disable, Windows Memory Integrity
    (HVCI) or Core Isolation.** Kernel-level targets are approached with both left
    enabled. Covers code, docs, reports, commit messages and chat. If a technique
    cannot work without disabling them, record that as a limitation and stop; do
    not offer the workaround. Checked by review only.

## Working method

12. **The push gate is installed, and never bypassed.** Run
    `python scripts/pre_push_gate.py install` before the first push from a clone;
    `--check` reports whether the managed hook is in place. The gate runs the
    discipline/privacy suite over the working tree and the same identity probes
    over every pushed commit's author, e-mail and message — the file scan alone
    cannot see commit metadata. `git push --no-verify` is not used. Commits and
    all local work stay unrestricted; this gates the irreversible step only.
    Checked by `pre_push_gate.py --check`. A bypass leaves no test failure, only a
    reflog entry, so this one is held by hand.
13. **Delegate bulky work; do not read it into the primary session.** Delegate when
    any of these is true: more than ~200 lines of a file would be read to answer one
    question; the work involves a disassembly, hexdump, `strings` or full decode
    listing; a full test log, or any command whose output size cannot be predicted;
    an exploration expected to take five or more steps; a sweep over several files to
    find where something lives. These are thresholds, not judgement calls — the
    measurement that produced them was a session of 917 Bash calls, 10 Agent calls
    and 0 Skill calls that pulled ~210k tokens of tool output into the lead. When a
    threshold is hit and delegation genuinely does not fit, write the artifact to a
    scratch path and read back only the lines that answer the question; state the
    exception in one sentence. The roster is `.codex/agents/`; the assessment order
    is `.agents/skills/attack-resistance-assessment/SKILL.md`. Department output is
    UNVERIFIED until checked against live evidence. Checked by review.
14. **Commit messages carry no `Co-Authored-By` trailer.** Write the message
    without one, whatever a tool's default attribution suggests. No machine check;
    this one is held by hand.
