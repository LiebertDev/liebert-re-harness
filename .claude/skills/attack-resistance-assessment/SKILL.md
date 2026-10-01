---
name: attack-resistance-assessment
description: The operational sequence for running a full attack-resistance assessment on an owned target end to end -- evidence collection, department fan-out and chaining, deliberate disagreement, curation, and rendering. Use when asked to run, perform, or produce an attack-resistance assessment on a binary, application, driver, or other target, not just to dispatch one department.
---

# attack-resistance-assessment

Nine department subagents live under `.claude/agents/` (`triage`, `attack-surface`, `recover`,
`bugclass-sink`, `reachability`, `crack-keygen`, `anticheat-driver`, `dynamic-repro`, `report`). Each
one states its own mission, real tool list, and model tier in its own frontmatter and body — this
skill is the order the whole assessment runs in, so it does not depend on the primary session
improvising the sequence each time. Case handling (lifecycle, redaction, the report template) is
`CASE_POLICY.md`, referenced from `CLAUDE.md`; this skill does not repeat it, but every department
is bound by it.

## Oracle rule (read this before anything else)

If the target has a recorded solve — a benchmark manifest, a test fixture, a write-up (for example an
entry already in `SOLVED_INDEX.md`) — tell every department, by path, not to read it. A reproduced
solve only means something if nothing in the run touched the answer.

## Sequence

This package has no standing orchestration layer: no session store, no automatic evidence ledger, no
`resume=True` render call. The sequence below uses what actually exists — the Task tool to fan
departments out, the CLI/module calls each department's own file names, and the real local
evidence/claim/report modules — not a custom dispatcher.

1. **Collect evidence first, mechanically.** Before fanning out, run the cheap structural calls that
   every department will otherwise re-run: `python -m liebert_re identify <path>`, `probe <path>`,
   and, for a PE, `pe <path> --sections/--imports/--exports`. Give every department the target path
   and whatever those calls returned (or where you wrote their JSON, if you saved it under
   `dataset/evidence/`) so departments cite a real command/field instead of re-deriving the same
   facts. If several tool calls may already answer a question, check
   `liebert_re.evidence.index.evidence_index(operation="by_target", target=...)` /
   `already_answered` before re-running them — this index exists specifically so the same expensive
   call is not paid for twice.

2. **Fan out the independent departments in parallel**, via the Agent/Task tool. Departments that
   answer different questions about the same evidence don't wait on each other — e.g. `attack-surface`
   (where input enters) and `crack-keygen` (what an attacker could achieve). Each department cites the
   evidence it used directly in its report (command + field, or a `dataset/evidence/*.json` path), so
   findings are checkable across departments and by the final render.

3. **Chain the ones with a real dependency.** `recover` (turn bytes into disassembly/structural
   facts) runs when another department is blocked on what the code actually does; `reachability` runs
   after `attack-surface` and `bugclass-sink` have both produced something to connect; `dynamic-repro`
   runs when a static reading needs settling — and runs within its own real ceiling (see its agent
   definition: no bounded emulator or isolated backend exists in this package yet). Do not parallelize
   a real dependency chain — run it in order.

4. **Let two departments answer the same question by different means, deliberately, when the stakes
   justify it.** A static reading and a validation-plan check can disagree — e.g. a literal near a
   prompt string reading like the accepted value on paper, versus the field actually resolving to a
   different value on the path `reachability` proves executes. Tell each department a disagreement is
   a useful result; do not tune either one toward what the other is expected to find.

5. **Curate before rendering.** Reject a hypothesis that describes an entry point without naming an
   attacker outcome, and reject one that rests only on an import or string appearing in the binary's
   tables — presence in a table is not evidence the code path exists or runs. State which of these two
   tests each rejection failed.

6. **Render with the real report layer.** `report` assembles the final write-up from
   `liebert_re.report.analysis_findings.render_finding_report`/`finding_report_generate`, not from a
   session store — there is none to resume. Close with `CASE_POLICY.md`'s three-answer report
   template (target, done, gained) and its `TARGET-NN` redaction rule for anything commercial.

## Rules every department must follow

- Non-empty `missing_evidence` forces `NEEDS_MORE_ANALYSIS`, and `build_security_hypothesis`
  (`liebert_re.report.analysis_findings`) never returns confidence above `MEDIUM` — this is enforced
  in code, not by convention. Departments must name their gaps honestly rather than emptying the list
  to look stronger — emptying it is the only way to make a false claim look confirmed.
- Before a department reports a capability as missing, it checks this install, not its memory of what
  an analysis harness usually has: `python -m liebert_re capabilities` (backed by
  `liebert_re.report.tool_families.published_family_report`) reports, per routing family, how many
  tools are named in the routing manifest versus actually implemented here. The primary session does
  not accept a bare "this can't do that" either — verify against that real output before it goes in a
  report.
- Every search a department runs is bounded, and the bound (attempts, time, file count) is stated in
  its report.
- No exploit code, no distributable keygen, no patched binary (`DISCLAIMER.md`'s "Out of scope").
  Describing the derivation — what the check is, what value or transform defeats it, and why — is the
  deliverable.
- Nothing produced during the assessment is committed with a real target name, an operator path, or a
  concrete offset/serial surviving past the final report — `CASE_POLICY.md` sections 1 and 4 apply to
  every intermediate department report, not only the rendered one.

## Verification

Department output is UNVERIFIED until the primary session checks it against live evidence (a
re-run command, a hash, a test, the evidence/claim index). A finding with no real evidence citation
backing a claim does not close the assessment.
