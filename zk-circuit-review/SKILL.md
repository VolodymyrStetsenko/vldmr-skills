---
name: zk-circuit-review
description: "Reviews zero-knowledge circuits for soundness and completeness bugs. Enumerates every signal and constraint in Circom, Noir, or Halo2 code, then hunts under-constrained outputs, non-deterministic witnesses, missing range checks, and unsafe hint usage. Triggers on 'zk circuit review', 'audit this circuit', 'check soundness', 'under-constrained', 'circom audit', 'noir audit', 'halo2 audit'."
---

# ZK Circuit Review

You are reviewing a zero-knowledge circuit for **soundness** (does the circuit
reject every invalid witness?) and **completeness** (does it accept every valid
one?). The dominant, most expensive bug class in ZK is *under-constraint*: a
signal the prover can freely choose because no constraint pins it down. This
skill finds those.

`$SKILL_DIR` is the directory containing this file. Resolve it from the path you
loaded this skill from (e.g. if this file is at `/x/zk-circuit-review/SKILL.md`,
then `$SKILL_DIR` = `/x/zk-circuit-review`).

Output goes into a `zk-review/` folder at the project root. Create it, write the
report there, and write nothing outside it.

## Progress tracking (MANDATORY)

Before anything else, create these three todos (all pending):

1. `Phase 1: Enumerate signals & constraints`
2. `Phase 2: Soundness & completeness analysis`
3. `Phase 3: Write zk-review report`

Keep exactly one todo in progress at a time. Mark a phase complete the moment
its work is done, and move the next to in progress in the same update.

## Phase 1 — Enumerate signals & constraints

Mark Phase 1 in progress, then determine scope:

- If the user names a path, use it. Otherwise auto-detect: look for `*.circom`,
  `*.nr`, or Rust files importing `halo2`. Circuits usually live under
  `circuits/`, `src/`, or `crates/`.
- Skip generated code, test vectors, and vendored libraries.

Run the enumerator (single Bash call, creating the output dir first):

```bash
mkdir -p zk-review && python3 "$SKILL_DIR/scripts/enumerate_circuit.py" <scope-path> --json zk-review/enumeration.json --report zk-review/scan-report.md && cat zk-review/enumeration.json
```

The JSON gives you, per file: templates/functions, `inputs`, `outputs`,
`intermediates`, constraint counts (`equality`, `assign`, `witness_only`), and a
list of `flags` — deterministic leads the script already found (under-constrained
witnesses, unconstrained outputs, unconstrained hint functions, gates without
selectors). These flags are **starting points, not conclusions**. The script
also writes `zk-review/scan-report.md` — an auto-generated, self-contained
summary of the deterministic pass (banner and progress go to stderr; stdout
stays machine-readable JSON).

In the same message, preload the taxonomy so it is in context for Phase 2:

- Read `$SKILL_DIR/references/vulnerability-classes.md`.

Mark Phase 1 complete.

## Phase 2 — Soundness & completeness analysis

The script gives you structure; you supply the reasoning. Walk the taxonomy in
`references/vulnerability-classes.md` against the enumerated circuit. For each
candidate, you MUST read the relevant source lines before making any claim.

Prioritize in this order:

1. **Every script flag.** For each flag, open the cited line and confirm or
   reject it. An `under-constrained-witness` is real only if you can describe a
   *different* witness value the circuit would still accept. If you cannot,
   downgrade it to a lead and say why.
2. **Output binding.** For each `signal output` (Circom) / public return (Noir) /
   instance column (Halo2), trace backward: is every output fully determined by
   the inputs *through constraints*, not merely through witness assignment
   (`<--`, `unconstrained fn`, bare `assign_advice`)? An output reachable only by
   assignment is unsound.
3. **Range and boolean checks.** Any signal used as a boolean, index, or bounded
   quantity must be explicitly constrained (`b*(b-1)===0` for booleans, an
   `n`-bit decomposition for ranges). Field elements wrap mod p — a "small"
   number is an assumption, never a guarantee.
4. **Determinism of hints.** Every witness computed off-circuit (`<--`,
   `unconstrained fn`, precomputed advice) must be re-derived or re-checked by a
   constraint. A hint that is trusted without a check is a free variable.
5. **Aliasing / non-uniqueness.** Can two distinct witnesses satisfy all
   constraints for the same public inputs? Division, modular inverse, and
   conditional selection are the usual sources.
6. **Completeness.** Would a legitimately valid input ever fail — e.g. an
   over-tight range, an assumed-nonzero denominator, or an unhandled edge value?

For each confirmed issue, capture: file, line, template/function, the exact
under- or over-constraint, a concrete witness or input that demonstrates it, the
impact (forge a proof / deny a valid prover), and the minimal constraint that
fixes it. Anything you cannot demonstrate with a concrete value is a **lead**,
recorded honestly as such.

Mark Phase 2 complete.

## Phase 3 — Write zk-review report

Write `zk-review/report.md` following the structure in
`$SKILL_DIR/references/report-template.md`. Rules:

- Findings are ordered by severity (Critical → High → Medium → Low → Lead).
- Every finding cites `file:line` and includes a concrete witness/input.
- The report states the constraint counts from Phase 1 so the reader sees the
  ratio of assignments to constraints at a glance.
- No fabrication. If soundness of a component could not be determined, say so and
  explain what evidence is missing.
- Delete `zk-review/enumeration.json` only if the user asked for a clean report;
  otherwise leave it as the machine-readable companion.

Finally, print the one-line verdict from the top of `report.md` to the terminal.

## Constraints

- Fully autonomous: Phases 1–3 need no user interaction.
- The enumerator never compiles or runs the circuit — it is static and
  deterministic. Do not claim dynamic results you did not produce.
- Keep the report focused: soundness first, gas/optimization never (out of scope).
