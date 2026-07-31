---
name: zk-circuit-review
description: "Reviews zero-knowledge circuits for soundness and completeness bugs. Enumerates every signal and constraint in Circom, Noir, or Halo2 code, then hunts under-constrained outputs, non-deterministic witnesses, missing range checks, and unsafe hint usage. Triggers on 'zk circuit review', 'audit this circuit', 'check soundness', 'under-constrained', 'circom audit', 'noir audit', 'halo2 audit'."
---

# ZK Circuit Review

## Purpose

Assess circuit soundness and completeness, with primary emphasis on signals
that are not uniquely constrained by the public statement and intended witness
relation.

Resolve `$SKILL_DIR` to the directory containing this file.

Write analysis artifacts under `zk-review/` at the project root. Do not modify
target source.

## Phase 1 — Enumerate signals & constraints

Determine scope as follows:

- If the user names a path, use it. Otherwise auto-detect: look for `*.circom`,
  `*.nr`, or Rust files importing `halo2`. Circuits usually live under
  `circuits/`, `src/`, or `crates/`.
- Skip generated code, test vectors, and vendored libraries.

Run the enumerator (single Bash call, creating the output dir first):

```bash
mkdir -p zk-review && python3 "$SKILL_DIR/scripts/enumerate_circuit.py" <scope-path> --json zk-review/enumeration.json --report zk-review/static-analysis.md && cat zk-review/enumeration.json
```

The JSON contains, per file: templates/functions, `inputs`, `outputs`,
`intermediates`, constraint counts (`equality`, `assign`, `witness_only`), and a
list of `flags`: deterministic source-pattern matches (under-constrained
witnesses, unconstrained outputs, unconstrained hint functions, gates without
selectors). Flags require source-level verification. The script
also writes `zk-review/static-analysis.md`, a generated representation of the
deterministic enumeration. It is an input to the manual analysis in Phase 2,
not the final assessment. Operational output is written to standard error;
standard output remains machine-readable JSON.

Read `$SKILL_DIR/references/vulnerability-classes.md` before Phase 2.

## Phase 2 — Soundness & completeness analysis

Apply `references/vulnerability-classes.md` to the enumerated circuit. Inspect
the relevant source lines before classifying each candidate.

Prioritize in this order:

1. **Every script flag.** Inspect the cited line and confirm or reject the
   detected condition. Classify an `under-constrained-witness` as a finding only
   when an alternate accepted witness value can be specified. Otherwise retain
   it as an analysis observation and record the unresolved condition.
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
5. **Aliasing / non-uniqueness.** Determine whether two distinct witnesses can
   satisfy all constraints for the same public inputs. Examine division,
   modular inverse, and conditional selection paths.
6. **Completeness.** Would a legitimately valid input ever fail — e.g. an
   over-tight range, an assumed-nonzero denominator, or an unhandled edge value?

For each confirmed issue, record: file, line, template/function, the exact
under- or over-constraint, a concrete witness or input that demonstrates it, the
impact (forge a proof / deny a valid prover), and the minimal constraint that
fixes it. Classify observations without a concrete demonstration as analysis
observations.

## Phase 3 — Write zk-review report

Write `zk-review/report.md` following the structure in
`$SKILL_DIR/references/report-template.md`. Rules:

- Use `enumeration.json`, `static-analysis.md`, and Phase 2 source review as
   inputs. `report.md` is the final analytical deliverable.

- Findings are ordered by severity. Analysis observations are listed separately.
- Every finding cites `file:line` and includes a concrete witness/input.
- The report includes Phase 1 constraint and assignment counts.
- Record unresolved soundness questions as limitations and identify the
   evidence required to resolve them.
- Delete `zk-review/enumeration.json` only if the user asked for a clean report;
  otherwise leave it as the machine-readable companion.

Print the report status line after writing the report.

## Constraints

- Execute all phases without user interaction unless scope is ambiguous or a
   required source path is unavailable.
- The enumerator performs static source analysis only. Do not attribute dynamic
   execution, compilation, proving, or verification coverage to its output.
- Gas and performance optimization are outside scope.
