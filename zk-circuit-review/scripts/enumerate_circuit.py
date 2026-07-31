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
access — it reads source and emits JSON. Heuristic flags are leads for a human
or agent to confirm, never final findings.

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
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


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


def iter_source_files(root: str, extensions: List[str]) -> List[str]:
    skip_dirs = {"node_modules", "lib", "target", ".git", "test", "tests", "mock", "mocks"}
    found: List[str] = []
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
    templates: List[str] = field(default_factory=list)
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    intermediates: List[str] = field(default_factory=list)
    components: int = 0
    constraints_equality: int = 0        # ===  (circom) / assert (noir)
    constraints_assign: int = 0          # <==  (assign + constrain)
    witness_only_assign: int = 0         # <--  (assign WITHOUT constrain)
    unconstrained_regions: int = 0       # noir `unconstrained fn` / circom `<--`
    gates: int = 0                       # halo2 create_gate
    advice_assignments: int = 0          # halo2 assign_advice
    flags: List[Flag] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Circom analysis
# --------------------------------------------------------------------------- #

_CIRCOM_TEMPLATE = re.compile(r"\btemplate\s+([A-Za-z_]\w*)\s*\(")
_CIRCOM_SIGNAL = re.compile(
    r"\bsignal\s+(input|output)?\s*([A-Za-z_]\w*)\s*(\[[^;]*\])?", re.MULTILINE
)
_CIRCOM_COMPONENT = re.compile(r"\bcomponent\s+[A-Za-z_]\w*")
_IDENT = re.compile(r"[A-Za-z_]\w*")


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
    witness_assigned: Dict[str, int] = {}   # base signal -> first line seen
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
            lhs = line.split("<--", 1)[0]
            idents = _IDENT.findall(lhs)
            if idents:
                witness_assigned.setdefault(_base_name(idents[-1]), lineno)
        elif "-->" in line:
            rep.witness_only_assign += 1
            rep.unconstrained_regions += 1
            rhs = line.split("-->", 1)[1]
            idents = _IDENT.findall(rhs)
            if idents:
                witness_assigned.setdefault(_base_name(idents[0]), lineno)

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

    # Advice cells assigned but a suspiciously low gate/enable count is a lead:
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

def detect_language(path: str, src: str) -> Optional[str]:
    ext = os.path.splitext(path)[1]
    if ext == ".circom":
        return "circom"
    if ext == ".nr":
        return "noir"
    if ext == ".rs" and ("halo2" in src or "ConstraintSystem" in src or "assign_advice" in src):
        return "halo2"
    return None


def analyze_file(path: str, forced: str = "auto") -> Optional[FileReport]:
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


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Enumerate ZK circuit signals and constraints.")
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("--json", help="write JSON report to this path")
    ap.add_argument("--lang", default="auto",
                    choices=["auto", "circom", "noir", "halo2"])
    args = ap.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    extensions = {"circom": [".circom"], "noir": [".nr"], "halo2": [".rs"],
                  "auto": [".circom", ".nr", ".rs"]}[args.lang]
    files = iter_source_files(args.path, extensions)

    reports: List[FileReport] = []
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
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"wrote {args.json}  ({summary['files_scanned']} files, "
              f"{summary['totals']['flags']} flags)")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
