# Case policy

Applies to any work on a specific target. `AGENTS.md` links here.

## 1. Record the class, not the binary

When a target is solved, keep what was learned about the **class of protection**,
not about that one binary.

Not this: "the crackme checked a serial at 0x401000 and compared it to a table."

This: "This protection class validates licences in-process using a self-checking
checksum over its own code. Patching the comparison trips the checksum. The
approach that defeats the class is to recompute the checksum after the change, or
to derive the key from the checksum inputs. Try first: find the checksum loop via
references to the code range it reads."

Test for any sentence in a report: would it help on a *different* binary that uses
the same protection class? If not, it is target-specific and does not survive.
Addresses, offsets, concrete serials and keys are target-specific. The harness is
not being specialised for any one crackme.

This section governs `Gained:` and every report on a `TARGET-NN` commercial or live
application. For a public crackme or CTF binary the report additionally records the
recovered answer; see section 3, "Public crackmes and CTF binaries".

## 2. Lifecycle

| State | Meaning | Artifacts |
|---|---|---|
| `active` | being worked | untouched; do not move, edit or clean them |
| `solved` | goal reached | purged automatically |
| `abandoned` | dropped | purged automatically |

On `solved` or `abandoned`, only generalized knowledge and the short report
survive. "Artifacts" means everything the case produced: samples, dumps, project
files, tool output, scratch scripts.

### The mechanism

`scripts/case_purge.py` (stdlib only, not shipped in the wheel). The layout it
understands, and only this layout:

```
cases/<name>/.liebert-case     marker (JSON); without it the tooling cannot see the case
cases/<name>/REPORT.md         kept
cases/<name>/knowledge/...     kept
cases/<name>/keep/...          kept
cases/<name>/**/*.writeup.md   kept (also writeup.md, writeup-*.md, *.knowledge.md)
cases/<name>/<everything else> scratch; purged on close, whatever its extension
```

The rule is an allow-list. On close a regular file survives only if it is on the keep
list above; everything else is purged, including `.txt`, `.json`, `.csv`, `.html`,
`.hex`, `.jsonl`, databases, archives, markdown notes and files with no extension.
There is no list of purgeable extensions to fall behind. Only the case being closed is
touched; a case that was not named in the close is never read for deletion.
`REPORT.md` is kept at the case root only.

- **Open:** `python scripts/case_purge.py init <name>` — creates the directory and
  the marker. A `cases/` directory without a marker is invisible to the purge and
  is reported at session start as unmarked.
- **Close:** put `case: solved <name>` or `case: abandoned <name>` in the commit
  message; the git post-commit hook acts on it
  (`case_purge.py install-hook`, `--check` to verify). `purge <name> --execute` is
  the manual escape hatch and is a dry run without `--execute`.
- **Reversible for seven days.** A purge *moves* files to
  `<os-temp>/liebert-re-quarantine/<case>/<UTC stamp>/` — never anywhere inside the
  repo. Entries expire after 7 days and are swept on every invocation. `restore
  <name>` puts one back and never overwrites. So anything worth keeping goes into
  `REPORT.md` or `knowledge/` **before** the close, not after.
- **Staleness.** An `active` case untouched for 14 days is reported at session
  start as probably abandoned (`scripts/session_health.py`, silent when healthy).
  Close it or abandon it; an indefinitely open case is how `cases/` becomes a heap.
- **Scope fence.** The purge refuses to delete outside the case root (exit code 3)
  and reports a partial failure rather than claiming success (exit code 4).
- `doctor` reports only and never moves anything: unmarked case directories,
  quarantine size and expiry, and the growth of `samples/ corpus/ out/ output/
  artifacts/ runs/` outside purge scope.

Nothing under `cases/**` is tracked except `REPORT.md`, `knowledge/` and the
marker. That is a `.gitignore` guarantee, not a habit. Do not copy artifacts
elsewhere to keep them past a close.

## 3. Case report

Written when a case closes and a report or commit is produced. Four answers,
nothing else. Aim for under 34 lines: the header takes 2, Target about 3, Done about
8 (up to 5 more when it carries a recovered answer and its derivation, see below),
Gained about 5, and Harness up to 14, enough for four numbered findings.

```
Case: <TARGET-NN or public name> | <category tag> | <solved|abandoned>

Target:  <redacted identity + technical category>
Done:    <what was done, 2-4 lines, method not addresses>
Gained:  <what to do first against this class next time; what did not work>
Harness: <what the run revealed about this package's own tooling>
```

`Gained:` is about the protection class and nothing else. A case in this project
exists to measure the harness as much as the target, and a harness finding is not
knowledge about a protection class, so it goes under `Harness:`, not into `Gained:`.
`Harness:` lists gaps, refusals and usability faults, numbered. For each one, say
whether it was already recorded in `docs/ROADMAP.md` or the external review, and
how that was checked (searched, or unchecked). A gap recorded in neither is the most
valuable kind: mark it `UNRECORDED` so it is not lost. A finding is kept and a weapon
is not: say what the tool did or refused to do, never how to use the target's
weakness. If a fix is under way, say so; do not report it as done.

### Public crackmes and CTF binaries: the answer is recorded

For a target section 4a permits naming, the report records the **recovered answer**
(or the **recipe**, when the answer depends on an input or on the date) under `Done:`,
together with enough of the derivation that a reader can check it against the
binary. This is not a weapon and must not be removed as one. A case marked `solved`
with no answer in it is an unfalsifiable claim: the answer is the evidence that the
harness drove the tools and reached the result, and without it a real solve cannot be
told from a guess, an inference, or a read writeup. A public crackme is free to
publish; nothing about a live product is involved.

It goes under `Done:`, not `Gained:`, because it is what the run produced and
`Gained:` is class-level only (above). The derivation stays method-level where it can;
addresses and offsets are kept only as far as a reader needs them to check the answer.

**The condition.** The answer counts as evidence **only if the harness derived it from
the binary.** If anyone in the chain (operator, agent, sub-agent) read the target's
published writeup, its comments, or a published solver before or during the run, the
report says so in `Done:` and the answer does **not** count as evidence of a solve.
An analyst who already knows the answer cannot measure where the harness stopped
helping, because they steer around the gaps without noticing. The invalidation leaves
no trace in the output, so it cannot be detected afterwards; that is why the report
must state the exposure rather than leave it to be assumed.

**Commercial or live applications (`TARGET-NN`) are unchanged:** no answer, no serial,
no patch, no walkthrough, in any section of any report.

Worked example (invented target):

```
Case: TARGET-07 | desktop CAD tool, in-process licence check, self-checksumming | solved

Target:  TARGET-07, commercial desktop application. Licence validated inside the
         main process; the validator hashes its own code section at start-up.
Done:    Found the validator by following string references from the licence
         dialog. Patching the branch directly failed because the self-check
         aborted. Located the checksum loop and confirmed it covers the patched range;
         the harness reported the range but could not say what the loop compares it to.
Gained:  For in-process validators with a self-checksum, find the hash loop before
         touching the licence branch; patch-then-debug cost the most time.
Harness: 1. No tool answers "does any loop read its own code range"; it would have
            found the validator immediately. UNRECORDED (searched ROADMAP and review).
```

The example names no function, address or key, and does not name the product
because it is commercial. Per `DISCLAIMER.md`, a report on a live product must not
read as circumvention instructions for it; stay at class level.

## 4. Redaction

### 4a. Target identity

- **Public crackmes and CTF binaries may be named.** Credit the author and link the
  original, as `docs/CORPUS.md` asks.
- **Commercial or live applications are never named**: not in reports, code,
  comments, tests, branch names or commit messages. They get a stable codename
  `TARGET-NN` (two digits, assigned once, never reused) and a technical category
  tag.
- The category tag carries the value: it lets later cases be matched to earlier
  ones. Format: comma-separated technical descriptors, e.g.
  `AAA title, kernel-mode anticheat, VM-obfuscated`. Describe the protection and
  the kind of software; not so precisely that the product is identifiable (no
  vendor, version or release year).
- The codename-to-product mapping is not stored in the repository. It lives in the
  private registry (section 6).

### 4b. Operator privacy

Nothing that identifies the machine or its owner may appear in any committed file,
report or commit message: real usernames, absolute home paths, hostnames, machine
identifiers (machine GUIDs, volume serials, MAC addresses, hardware IDs), licence
keys, credentials, tokens.

Substitute:

| Real | Write |
|---|---|
| user name | `<USER>` |
| absolute home path | `C:\Users\<USER>\...`, `<HOME>/...` |
| workspace or sample directory | `<WORKSPACE>/...`, `<SAMPLES>/...` |
| host / computer name | `<HOST>` |
| machine GUID, volume serial, MAC | `<MACHINE-ID>` |
| the operator's own licence key | `<LICENCE-KEY>` |
| password, API key, token | `<REDACTED>` |

Pasted tool output is the realistic leak. IDA, Ghidra, debuggers and crash dumps
embed absolute paths (PDB paths, project paths, module lists, stack frames) and
the host name. Redact every pasted block before it enters a file, then reread it.
Prefer quoting the one relevant line to pasting a block.

Checked partly: `tests/test_repo_discipline.py::test_no_machine_specific_user_paths`
fails on `C:\Users\<name>`-style and `/home/<name>`-style paths in tracked files
(the `<USER>` placeholders above do not trigger it). It does not see hostnames,
machine IDs, keys, tokens or commit messages; those are the author's duty.

## 5. Kernel-level targets

The harness never disables, and never tells the operator to disable, Windows
Memory Integrity (HVCI) or Core Isolation. Kernel-level targets are approached
with both enabled. See `AGENTS.md` rule 11.

## 6. Private target registry (codenames and the product denylist)

One file outside the repository serves two jobs: it is the codename registry (which
`TARGET-NN` is which product, and which earlier case a new target matches) and the
list of names the privacy gate refuses to let into any tracked file.

- **Location:** `~/.liebert-re/targets.txt` (the user profile directory, not the
  repo). Override with the `LIEBERT_RE_TARGETS` environment variable.
- **Format**, one target per line, `|`-separated, names `;`-separated:

  ```
  TARGET-NN | <real name>; <other name>; <driver/service/process short name> | <category tag>
  ```

  `#` lines and blank lines are ignored. `NN` is two or more digits, assigned once,
  never reused (a duplicate codename makes the file invalid). List every name the
  target goes by: product, vendor, driver, service and process short names, file
  names without extension (3+ characters each). The category tag is the same tag
  that goes in the report (4a). Placeholder shape only; never copy real lines into
  the repo, a report or a commit message:

  ```
  TARGET-NN | <product name>; <vendor name>; <service short name> | <category tag>
  ```

- **Allocating a number:** take the highest `NN` in this file, add one. Check
  `cases/` and the report headers too, in case a case was started and never listed.
- **Matching a new target to a past case:** search this file by name or by tag
  (`grep -i` on the file), then open the report for that `TARGET-NN`.
- **Adding a target:** add its line here before work starts. That one edit is what
  protects it: `tests/test_repo_discipline.py` reads this file at test time and
  fails if any tracked file or file name contains one of the names.
- **When the file is absent** (fresh clone, CI, another machine): the product rule
  is inactive, and `test_product_rule_is_active_or_says_why` SKIPS with the reason
  printed (`pytest -rs`). Shape rules and the operator-identity rules still run. A
  file that exists but is malformed fails the suite, naming only the line number.
- **Back it up** (section 7). It holds real names: never commit it, never paste its
  lines anywhere tracked.

## 7. Where the private files live (restore path)

`CASE_POLICY.md` is tracked and published. The tracked copy is the source of truth
for this policy, and no out-of-tree copy of it is authoritative. Do not keep a
private master of it; edit it in the repo and commit it.

The working rules live in the tracked `AGENTS.md`. The local, gitignored `CLAUDE.md`
holds the single line `@AGENTS.md` and nothing else, so it cannot drift from the
tracked rules; a fresh clone or a clean of ignored files deletes it, and recreating it
is writing that one line. Do not put rules in it. The target registry is the one
private file left:

- `~/.liebert-re/targets.txt` (section 6; the registry is stored only there)

There is no sync tool by design.

## 8. Annotated analysis data at case close

Annotations written through the harness (`ida_annotations_apply`) live in their own
tree, `dataset/ida_annotated/`, apart from the re-derivable analysis cache. They are
the operator's work and are never evicted automatically.

- **Closing a case reports them; it does not delete them.** A close reports the
  annotated scopes that belong to the case (input hash, label, published version,
  bytes held, kept candidates). Deleting them requires an explicit flag. Closing a
  case alone never deletes annotated data.
- **No accidental deletion.** `scripts/case_purge.py` treats the data directory as
  out of scope and does not touch this tree.
- **The only deletion path** is the annotated-data cleanup operation,
  `ida_annotations_purge`. It deletes nothing by default: a call without
  confirmation returns a report only. It names every target, and the confirmation
  is bound to what it reported. A wildcard delete is refused.
- **Status: partly implemented.** `ida_annotations_purge` ships in
  `liebert_re/tools/ida.py` and is callable as a Python function (it is listed in
  `ida_status`'s operations), with the confirmation behaviour above; it has no
  `liebert_re` CLI subcommand. The close-time report and the flag in
  `scripts/case_purge.py` do not exist yet (none of its subcommands touches this
  tree), so closing a case neither reports nor deletes annotated data; that part
  records the decision, not working behaviour. How a label maps to a case name is a
  separate, open decision.
