#!/usr/bin/env python3
"""
enumerate_circuit.py — deterministic signal & constraint enumerator for
zero-knowledge circuits.

Part of the `zk-circuit-review` skill.

Supported inputs:
  - Circom  (*.circom)  — full signal/constraint model with an under-constrained
                          witness heuristic.
  - Noir    (*.nr)      — constraint (assert) and unconstrained-region model.
  - Halo2   (*.rs)      — gate / advice-assignment surface (structural only).

The goal is a *reproducible* map of what the circuit declares versus what it
actually constrains. It performs no proving, no compilation, and no network
access — it reads source and emits JSON. Flags are source-pattern matches that
require verification before classification as findings.

Usage:
  enumerate_circuit.py <path> [--json OUT] [--lang circom|noir|halo2|auto]

Exit codes:
  0  success (with or without flags)
  2  bad usage / path not found
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Branding & reporting
# --------------------------------------------------------------------------- #

_BANNER = r"""
█   █  █      ████   █   █  ████
█   █  █      █   █  ██ ██  █   █
█   █  █      █   █  █ █ █  ████
 █ █   █      █   █  █   █  █  █
  █    █████  ████   █   █  █   █

 ████  █   █  ███  █      █       ████
█      █  █    █   █      █      █
 ███   ███     █   █      █       ███
    █  █  █    █   █      █          █
████   █   █  ███  █████  █████  ████
"""

_SEVERITY = {
    "unconstrained-output": "Critical",
    "under-constrained-witness": "High",
    "unconstrained-fn": "High",
    "no-constraints": "High",
    "unused-public-input": "Medium",
    "advice-without-gate": "Medium",
    "gate-without-selector": "Medium",
}


def _print_banner(subtitle: str) -> None:
    """Print the Skills banner to stderr (stdout stays machine-readable)."""
    print(_BANNER, file=sys.stderr)
    print(f"  Skills · {subtitle}\n", file=sys.stderr)


def _read_version() -> str:
    try:
        with open(os.path.join(os.path.dirname(__file__), "..", "VERSION")) as fh:
            return fh.read().strip()
    except OSError:
        return "?"


def build_report(summary: dict) -> str:
    """Render the normative markdown summary for an enumeration result."""
    t = summary["totals"]
    root = os.path.basename(summary["root"].rstrip("/")) or summary["root"]
    langs = ", ".join(summary.get("languages") or []) or "—"
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    flags = summary["flags"]

    L: list[str] = []
    L.append(f"# ZK Circuit Review — {root}")
    L.append("")
    L.append(f"> Skills · `zk-circuit-review` v{_read_version()} · {date} (UTC)")
    L.append("")
    L.append(f"**Scope:** `{summary['root']}` · {summary['files_scanned']} file(s) · "
             f"languages: {langs}")
    L.append("")
    L.append("## Summary")
    L.append("")
    L.append("| metric | value |")
    L.append("| --- | ---: |")
    L.append(f"| Templates / functions | {t['templates']} |")
    L.append(f"| Input signals | {t['inputs']} |")
    L.append(f"| Output signals | {t['outputs']} |")
    L.append(f"| Equality constraints (`===`/assert) | {t['equality_constraints']} |")
    L.append(f"| Assign+constrain (`<==`) | {t['assign_constraints']} |")
    L.append(f"| Witness-only assignments (`<--`) | {t['witness_only_assignments']} |")
    L.append(f"| Unconstrained regions | {t['unconstrained_regions']} |")
    L.append(f"| **Flags** | **{t['flags']}** |")
    L.append("")
    L.append("## Analysis observations")
    L.append("")
    if not flags:
        L.append("No implemented detection pattern matched the analyzed source. "
                 "Fiat–Shamir transcript construction, trusted-setup provenance, and "
                 "imported dependency graphs require separate assessment.")
    else:
        L.append("The following static-analysis observations require source-level "
                 "verification before classification as findings.")
        L.append("")
        L.append("| # | Severity | Kind | Signal | Location | Note |")
        L.append("| ---: | --- | --- | --- | --- | --- |")
        for i, f in enumerate(flags, 1):
            sev = _SEVERITY.get(f["kind"], "Unrated")
            loc = f"{os.path.basename(f['file'])}:{f['line']}"
            L.append(f"| {i} | {sev} | `{f['kind']}` | `{f['signal']}` | {loc} | {f['note']} |")
    L.append("")
    L.append("## Analysis status")
    L.append("")
    L.append(_verdict(flags))
    L.append("")
    L.append("## Method & limits")
    L.append("")
    L.append("- Deterministic, comment-stripped source analysis (no proving, no network).")
    L.append("- Flags require verification with an alternate witness or a constraint "
             "trace before classification as findings.")
    L.append("- Library sub-circuits imported from `node_modules`/`target` are not followed.")
    return "\n".join(L) + "\n"


def _verdict(flags: list[dict]) -> str:
    if not flags:
        return ("**NO FLAGS.** No implemented under-constraint or unused-input "
                "detection pattern matched the analyzed source.")
    crit = [f for f in flags if _SEVERITY.get(f["kind"]) in {"Critical", "High"}]
    if crit:
        return (f"**REVIEW REQUIRED.** {len(crit)} observation(s) are mapped to "
                "high-impact soundness classes and require manual verification.")
    return (f"**REVIEW REQUIRED.** {len(flags)} observation(s) require manual "
        "verification and disposition.")



# --------------------------------------------------------------------------- #
# Comment stripping (shared)
# --------------------------------------------------------------------------- #

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")


def strip_comments(src: str) -> str:
    """Remove /* */ and // comments while preserving line count for line refs."""
    def _block_repl(m: re.Match) -> str:
        # keep newlines so reported line numbers stay accurate
        return "\n" * m.group(0).count("\n")

    src = _BLOCK_COMMENT.sub(_block_repl, src)
    src = _LINE_COMMENT.sub("", src)
    return src


def iter_source_files(root: str, extensions: list[str]) -> list[str]:
    skip_dirs = {"node_modules", "lib", "target", ".git", "test", "tests", "mock", "mocks"}
    found: list[str] = []
    if os.path.isfile(root):
        return [root] if os.path.splitext(root)[1] in extensions else []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            if os.path.splitext(name)[1] in extensions:
                found.append(os.path.join(dirpath, name))
    return sorted(found)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Flag:
    file: str
    line: int
    kind: str
    signal: str
    note: str


@dataclass
class FileReport:
    file: str
    language: str
    templates: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    intermediates: list[str] = field(default_factory=list)
    components: int = 0
    constraints_equality: int = 0        # ===  (circom) / assert (noir)
    constraints_assign: int = 0          # <==  (assign + constrain)
    witness_only_assign: int = 0         # <--  (assign WITHOUT constrain)
    unconstrained_regions: int = 0       # noir `unconstrained fn` / circom `<--`
    gates: int = 0                       # halo2 create_gate
    advice_assignments: int = 0          # halo2 assign_advice
    flags: list[Flag] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Circom analysis
# --------------------------------------------------------------------------- #

_CIRCOM_TEMPLATE = re.compile(r"\btemplate\s+([A-Za-z_]\w*)\s*\(")
_CIRCOM_SIGNAL = re.compile(
    r"\bsignal\s+(input|output)?\s*([A-Za-z_]\w*)\s*(\[[^;]*\])?", re.MULTILINE
)
_CIRCOM_COMPONENT = re.compile(r"\bcomponent\s+[A-Za-z_]\w*")
_IDENT = re.compile(r"[A-Za-z_]\w*")

# The assignment target of a `<--` / `-->` is the signal reference directly
# adjacent to the operator, ignoring array indices and member access. This is
# robust to single-line `for` loops such as `for (i=0; i<256; i++) out[i] <-- x`
# where the naive "first/last identifier" heuristics pick the loop variable.
_WITNESS_LHS = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*|\.[A-Za-z_]\w*\s*)*<--")
_WITNESS_RHS = re.compile(r"-->\s*([A-Za-z_]\w*)")


def _base_name(sig: str) -> str:
    """Strip array indexing so `in[3]` and `in[0]` map to the same signal `in`."""
    return sig.split("[", 1)[0].strip()


def analyze_circom(path: str, src: str) -> FileReport:
    rep = FileReport(file=path, language="circom")
    clean = strip_comments(src)

    rep.templates = sorted(set(_CIRCOM_TEMPLATE.findall(clean)))
    rep.components = len(_CIRCOM_COMPONENT.findall(clean))

    inputs, outputs, intermediates = set(), set(), set()
    for m in _CIRCOM_SIGNAL.finditer(clean):
        kind, name = m.group(1), m.group(2)
        if kind == "input":
            inputs.add(name)
        elif kind == "output":
            outputs.add(name)
        else:
            intermediates.add(name)
    rep.inputs, rep.outputs, rep.intermediates = (
        sorted(inputs), sorted(outputs), sorted(intermediates)
    )

    # Constraint operators. Order matters: match <== and <-- before < / =.
    # Collect, per line, the LHS signal being written and how.
    witness_assigned: dict[str, int] = {}   # base signal -> first line seen
    constrained: set = set()                 # base signals appearing in === or <==

    for lineno, raw in enumerate(clean.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue

        # equality constraint  a === b
        if "===" in line:
            rep.constraints_equality += 1
            for ident in _IDENT.findall(line):
                constrained.add(ident)

        # assign + constrain  a <== expr   (also right form expr ==> a)
        if "<==" in line or "==>" in line:
            rep.constraints_assign += 1
            for ident in _IDENT.findall(line):
                constrained.add(ident)

        # witness-only assignment  a <-- expr   (or expr --> a). The written
        # signal is the LHS of `<--` or the RHS of `-->`; the other side is an
        # expression, not a target, so we must not treat its identifiers as
        # witness signals.
        if "<--" in line:
            rep.witness_only_assign += 1
            rep.unconstrained_regions += 1
            m = _WITNESS_LHS.search(line)
            if m:
                witness_assigned.setdefault(_base_name(m.group(1)), lineno)
        elif "-->" in line:
            rep.witness_only_assign += 1
            rep.unconstrained_regions += 1
            m = _WITNESS_RHS.search(line)
            if m:
                witness_assigned.setdefault(_base_name(m.group(1)), lineno)

    # Under-constrained heuristic: a signal assigned only via `<--`
    # and never appearing in a `===` / `<==` constraint is a classic
    # under-constrained witness (the prover can choose it freely).
    for sig, lineno in witness_assigned.items():
        if sig not in constrained and sig not in rep.outputs:
            rep.flags.append(Flag(
                file=path, line=lineno, kind="under-constrained-witness",
                signal=sig,
                note=("assigned with `<--` (witness only) and never appears in a "
                      "`===`/`<==` constraint — prover can choose this value freely"),
            ))

    # Output signals never constrained at all are especially dangerous.
    for out in rep.outputs:
        if out not in constrained and out in witness_assigned:
            rep.flags.append(Flag(
                file=path, line=witness_assigned[out],
                kind="unconstrained-output", signal=out,
                note="declared `signal output` but only witness-assigned — "
                     "the proof does not bind this public output to the computation",
            ))

    # 0xPARC class 5 — "unused public inputs optimized out". A `signal input`
    # that never appears in any expression or constraint is silently removed by
    # the Circom compiler, so the binding it was meant to enforce disappears. A
    # signal whose base name occurs only once in the source (its own
    # declaration) is such an unused input.
    for inp in rep.inputs:
        occ = len(re.findall(r"\b" + re.escape(inp) + r"\b", clean))
        if occ <= 1:
            decl_line = next(
                (i for i, raw in enumerate(clean.splitlines(), 1)
                 if re.search(r"\bsignal\s+input\b[^;]*\b" + re.escape(inp) + r"\b", raw)),
                1)
            rep.flags.append(Flag(
                file=path, line=decl_line, kind="unused-public-input", signal=inp,
                note="declared `signal input` but never used in any constraint or "
                     "expression — Circom optimizes it away, so it binds nothing "
                     "(0xPARC class 5: unused public inputs optimized out)",
            ))

    return rep


# --------------------------------------------------------------------------- #
# Noir analysis
# --------------------------------------------------------------------------- #

_NOIR_FN = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*\(")
_NOIR_UNCONSTRAINED_FN = re.compile(r"\bunconstrained\s+fn\s+([A-Za-z_]\w*)")
_NOIR_ASSERT = re.compile(r"\bassert(_eq)?\s*\(")


def analyze_noir(path: str, src: str) -> FileReport:
    rep = FileReport(file=path, language="noir")
    clean = strip_comments(src)

    rep.templates = sorted(set(_NOIR_FN.findall(clean)))
    rep.constraints_equality = len(_NOIR_ASSERT.findall(clean))

    unconstrained = _NOIR_UNCONSTRAINED_FN.findall(clean)
    rep.unconstrained_regions = len(unconstrained)
    for lineno, raw in enumerate(clean.splitlines(), start=1):
        if "unconstrained" in raw and "fn" in raw:
            m = _NOIR_UNCONSTRAINED_FN.search(raw)
            if m:
                rep.flags.append(Flag(
                    file=path, line=lineno, kind="unconstrained-fn",
                    signal=m.group(1),
                    note="`unconstrained fn` result is a hint, not a proof — every "
                         "value it returns must be re-checked with an `assert` in "
                         "constrained code before it is trusted",
                ))

    # A main with public/return values but zero asserts constrains nothing.
    if "fn main" in clean and rep.constraints_equality == 0:
        line = next((i for i, r in enumerate(clean.splitlines(), 1)
                     if "fn main" in r), 1)
        rep.flags.append(Flag(
            file=path, line=line, kind="no-constraints",
            signal="main",
            note="`main` contains no `assert`/`assert_eq` — the circuit imposes no "
                 "constraints and accepts any witness",
        ))
    return rep


# --------------------------------------------------------------------------- #
# Halo2 analysis (structural surface only)
# --------------------------------------------------------------------------- #

_HALO2_GATE = re.compile(r"\.create_gate\s*\(")
_HALO2_ADVICE = re.compile(r"\.assign_advice\s*\(")
_HALO2_CONSTRAIN_EQ = re.compile(r"\.constrain_equal\s*\(")
_HALO2_ENABLE = re.compile(r"\.enable\s*\(")


def analyze_halo2(path: str, src: str) -> FileReport:
    rep = FileReport(file=path, language="halo2")
    clean = strip_comments(src)

    rep.gates = len(_HALO2_GATE.findall(clean))
    rep.advice_assignments = len(_HALO2_ADVICE.findall(clean))
    rep.constraints_equality = len(_HALO2_CONSTRAIN_EQ.findall(clean))
    enables = len(_HALO2_ENABLE.findall(clean))

    # Advice cells assigned with a low gate/enable count require review:
    # cells may be assigned into the trace without a selector enabling any gate
    # over them.
    if rep.advice_assignments > 0 and rep.gates == 0:
        line = next((i for i, r in enumerate(clean.splitlines(), 1)
                     if ".assign_advice" in r), 1)
        rep.flags.append(Flag(
            file=path, line=line, kind="advice-without-gate", signal="(region)",
            note="advice cells are assigned but this file defines no `create_gate` — "
                 "confirm the assigned cells are constrained by a gate defined "
                 "elsewhere, otherwise they are free witness",
        ))
    if rep.gates > 0 and enables == 0:
        line = next((i for i, r in enumerate(clean.splitlines(), 1)
                     if ".create_gate" in r), 1)
        rep.flags.append(Flag(
            file=path, line=line, kind="gate-without-selector", signal="(gate)",
            note="a gate is created but no selector `.enable(...)` is visible in "
                 "this file — a gate that is never enabled constrains nothing",
        ))
    return rep


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

def detect_language(path: str, src: str) -> str | None:
    ext = os.path.splitext(path)[1]
    if ext == ".circom":
        return "circom"
    if ext == ".nr":
        return "noir"
    if ext == ".rs" and ("halo2" in src or "ConstraintSystem" in src or "assign_advice" in src):
        return "halo2"
    return None


def analyze_file(path: str, forced: str = "auto") -> FileReport | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError:
        return None
    lang = forced if forced != "auto" else detect_language(path, src)
    if lang == "circom":
        return analyze_circom(path, src)
    if lang == "noir":
        return analyze_noir(path, src)
    if lang == "halo2":
        return analyze_halo2(path, src)
    return None


def _write_text(path: str, content: str) -> bool:
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    except OSError as exc:
        print(f"error: failed to write {path}: {exc}", file=sys.stderr)
        return False
    return True


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Enumerate ZK circuit signals and constraints.")
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("--json", help="write JSON report to this path")
    ap.add_argument("--report", help="write a markdown review report to this path")
    ap.add_argument("--lang", default="auto",
                    choices=["auto", "circom", "noir", "halo2"])
    ap.add_argument("--no-banner", action="store_true", help="suppress the banner")
    args = ap.parse_args(argv)

    if not args.no_banner:
        _print_banner("zk-circuit-review · soundness & under-constraint review")

    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    extensions = {"circom": [".circom"], "noir": [".nr"], "halo2": [".rs"],
                  "auto": [".circom", ".nr", ".rs"]}[args.lang]
    files = iter_source_files(args.path, extensions)

    reports: list[FileReport] = []
    for f in files:
        rep = analyze_file(f, args.lang)
        if rep is not None:
            reports.append(rep)

    all_flags = [flag for r in reports for flag in r.flags]
    summary = {
        "root": os.path.abspath(args.path),
        "files_scanned": len(reports),
        "languages": sorted({r.language for r in reports}),
        "totals": {
            "templates": sum(len(r.templates) for r in reports),
            "inputs": sum(len(r.inputs) for r in reports),
            "outputs": sum(len(r.outputs) for r in reports),
            "equality_constraints": sum(r.constraints_equality for r in reports),
            "assign_constraints": sum(r.constraints_assign for r in reports),
            "witness_only_assignments": sum(r.witness_only_assign for r in reports),
            "unconstrained_regions": sum(r.unconstrained_regions for r in reports),
            "flags": len(all_flags),
        },
        "flags": [asdict(f) for f in all_flags],
        "files": [asdict(r) for r in reports],
    }

    payload = json.dumps(summary, indent=2)
    if args.json:
        if not _write_text(args.json, payload):
            return 2
        print(f"wrote {args.json}  ({summary['files_scanned']} files, "
              f"{summary['totals']['flags']} flags)")
    else:
        print(payload)

    if args.report:
        if not _write_text(args.report, build_report(summary)):
            return 2
        print(f"wrote {args.report}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
