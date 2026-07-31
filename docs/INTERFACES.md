# Interface Specification

## Applicability

This document defines the unchanged command-line and output contracts used by
release `2.0.0`. The Agent Skills procedures orchestrate autonomous source
review and mandatory reporting around these deterministic Phase 1 interfaces.

## Runtime Requirements

| Requirement | Specification |
| --- | --- |
| Python | 3.9 or later |
| Python dependencies | Standard library only |
| Input encoding | UTF-8 source text |
| Network access | None |
| Target execution | None |
| Target compilation | None |

## Common Options

| Argument | Required | Description |
| --- | :---: | --- |
| `path` | Yes | Source file or directory to analyze |
| `--json PATH` | No | Write the JSON result to `PATH` instead of standard output |
| `--report PATH` | No | Write a markdown summary derived from the JSON result |
| `--no-banner` | No | Suppress the standard-error banner |

Parent directories for `--json` and `--report` are created when necessary.
Existing output files are replaced.

## Commands

### ZK circuit enumeration

```text
python3 enumerate_circuit.py PATH [--json PATH] [--report PATH]
                             [--lang auto|circom|noir|halo2] [--no-banner]
```

`--lang auto` selects source by extension: `.circom`, `.nr`, and `.rs`.
Explicit language selection restricts the accepted extensions.

### Verifier integration scan

```text
python3 scan_verifier.py PATH [--json PATH] [--report PATH] [--no-banner]
```

The scanner reads Solidity source (`.sol`) and excludes common vendor, test,
build-output, and repository-metadata directories.

### EVM invariant enumeration

```text
python3 enumerate_evm.py PATH [--json PATH] [--report PATH] [--no-banner]
```

The scanner reads Solidity source (`.sol`) and excludes common vendor, test,
build-output, and repository-metadata directories.

## Standard Streams

| Stream | Content |
| --- | --- |
| Standard output | JSON result when `--json` is not supplied; output-path confirmation when `--json` is supplied |
| Standard error | Banner, report-path confirmation, and path validation errors |

Consumers requiring JSON on standard output should omit `--json` and either use
`--no-banner` or keep standard error separate.

## Exit Status

| Status | Meaning |
| ---: | --- |
| `0` | Analysis completed, including runs that produced flags |
| `2` | Invalid arguments or source path not found |
| Other non-zero | Unhandled runtime or I/O failure |

Flags do not change the exit status. Automation must inspect `totals.flags`.

## Terminology

- `flag` refers exclusively to a machine-readable object in a JSON `flags`
    array.
- `analysis observation` refers to an unverified interpretation requiring
    source or system-level review.
- `finding` refers to a verified security-property violation.

## Common JSON Conventions

- Paths are absolute paths from the analysis environment.
- Line numbers are one-based.
- Arrays retain deterministic source-path ordering.
- `flags` contains machine-readable source-pattern matches, not confirmed
    vulnerabilities.
- `files_scanned` counts files for which a report object was generated.

## ZK Circuit JSON

Top-level fields:

| Field | Type | Description |
| --- | --- | --- |
| `root` | string | Absolute analysis scope |
| `files_scanned` | integer | Number of analyzed source files |
| `languages` | array of strings | Languages detected in scope |
| `totals` | object | Aggregate template, signal, constraint, witness, region, and flag counts |
| `flags` | array | Flattened machine-readable flags |
| `files` | array | Per-file circuit report objects |

Flag object:

| Field | Type | Nullable | Description |
| --- | --- | :---: | --- |
| `file` | string | No | Absolute source path |
| `line` | integer | No | One-based source line |
| `kind` | string | No | Stable flag identifier |
| `signal` | string | No | Affected signal or region identifier |
| `note` | string | No | Detection rationale |

File object:

| Field | Type |
| --- | --- |
| `file`, `language` | string |
| `templates`, `inputs`, `outputs`, `intermediates` | array of strings |
| `components`, `constraints_equality`, `constraints_assign` | integer |
| `witness_only_assign`, `unconstrained_regions`, `gates`, `advice_assignments` | integer |
| `flags` | array of flag objects |

## Verifier Bridge JSON

Top-level fields:

| Field | Type | Description |
| --- | --- | --- |
| `root` | string | Absolute analysis scope |
| `files_scanned` | integer | Number of analyzed Solidity files |
| `verifier_contracts` | array of strings | Files classified as proof verifiers |
| `consumer_contracts` | array of strings | Files containing verifier call sites |
| `totals` | object | Verifier, consumer, call-site, and flag counts |
| `flags` | array | Flattened machine-readable integration flags |
| `files` | array | Relevant per-file verifier/consumer reports |

Flag object:

| Field | Type | Nullable | Description |
| --- | --- | :---: | --- |
| `file` | string | No | Absolute source path |
| `line` | integer | No | One-based source line |
| `kind` | string | No | Stable flag identifier |
| `note` | string | No | Detection rationale |

Call-site object:

| Field | Type | Nullable |
| --- | --- | :---: |
| `file`, `receiver`, `method`, `args` | string | No |
| `line` | integer | No |

File object:

| Field | Type |
| --- | --- |
| `file` | string |
| `is_verifier`, `has_nullifier_tracking`, `has_replay_guard`, `binds_context` | boolean |
| `verifier_settable`, `verifier_immutable` | boolean |
| `consumer_calls` | array of call-site objects |
| `flags` | array of flag objects |

## EVM Invariant JSON

Top-level fields:

| Field | Type | Description |
| --- | --- | --- |
| `root` | string | Absolute analysis scope |
| `files_scanned` | integer | Number of analyzed Solidity files |
| `totals` | object | Contract, function, entry-point, permissionless-entry-point, conservation-seed, and flag counts |
| `flags` | array | Flattened machine-readable EVM flags |
| `files` | array | Per-file contract and function reports |

Flag object:

| Field | Type | Nullable | Description |
| --- | --- | :---: | --- |
| `file` | string | No | Absolute source path |
| `line` | integer | No | One-based source line |
| `kind` | string | No | Stable flag identifier |
| `function` | string | No | Function name or `(file)` for file-level flags |
| `note` | string | No | Detection rationale |

Function object:

| Field | Type |
| --- | --- |
| `name`, `visibility`, `mutability` | string |
| `line` | integer |
| `modifiers` | array of strings |
| `writes_state`, `external_call`, `entry_point` | boolean |

File object:

| Field | Type |
| --- | --- |
| `file` | string |
| `contracts` | array of strings |
| `functions` | array of function objects |
| `conservation_seed` | boolean |
| `flags` | array of flag objects |

## Compatibility

Additive JSON fields may be introduced in a minor release. Removal, renaming,
type changes, or semantic changes to existing fields require a major release.
Flag identifiers are part of the machine-readable interface.
