# ZK Circuit Review — circuits

> VLDMR Skills · `zk-circuit-review` v1.2.0 · 2026-07-31 (UTC)

**Scope:** `/home/volodymyr-sec/projects/_audit-targets/circomlib/circuits` · 57 file(s) · languages: circom

## Summary

| metric | value |
| --- | ---: |
| Templates / functions | 107 |
| Input signals | 188 |
| Output signals | 70 |
| Equality constraints (`===`/assert) | 51 |
| Assign+constrain (`<==`) | 918 |
| Witness-only assignments (`<--`) | 17 |
| Unconstrained regions | 17 |
| **Leads** | **3** |

## Leads

Each row is a **lead** to confirm against the circuit, not a final finding.

| # | Severity | Kind | Signal | Location | Note |
| ---: | --- | --- | --- | --- | --- |
| 1 | Medium | `unused-public-input` | `st_na` | smtprocessorlevel.circom:49 | declared `signal input` but never used in any constraint or expression — Circom optimizes it away, so it binds nothing (0xPARC class 5: unused public inputs optimized out) |
| 2 | Medium | `unused-public-input` | `st_i0` | smtverifierlevel.circom:43 | declared `signal input` but never used in any constraint or expression — Circom optimizes it away, so it binds nothing (0xPARC class 5: unused public inputs optimized out) |
| 3 | Medium | `unused-public-input` | `st_na` | smtverifierlevel.circom:46 | declared `signal input` but never used in any constraint or expression — Circom optimizes it away, so it binds nothing (0xPARC class 5: unused public inputs optimized out) |

## Verdict

**Leads to confirm.** 3 lower-severity lead(s) (e.g. unused public inputs). Confirm and either constrain or document.

## Method & limits

- Deterministic, comment-stripped source analysis (no proving, no network).
- Leads are heuristic; confirm each with a concrete second witness or a constraint trace before reporting as a finding.
- Library sub-circuits imported from `node_modules`/`target` are not followed.
