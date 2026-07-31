#!/usr/bin/env python3
"""
enumerate_evm.py — deterministic entry-point, access-control, and invariant-seed
enumerator for Solidity codebases.

Part of the `evm-invariant-scan` skill.

It builds a reproducible map of a protocol's attack surface without compiling:
  - every contract and its public/external functions,
  - each function's visibility, mutability, access modifiers, and whether it
    writes state or makes an external call,
  - deterministic leads: permissionless state changes, external calls without a
    reentrancy guard, unchecked low-level calls,
  - invariant seeds: balance mappings paired with a supply variable
    (conservation candidates).

No network, no compilation. Function bodies are resolved by brace matching so
multi-line signatures are handled correctly.

Usage:
  enumerate_evm.py <path> [--json OUT]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple


_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")


def strip_comments(src: str) -> str:
    def _block_repl(m: re.Match) -> str:
        return "\n" * m.group(0).count("\n")
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub(_block_repl, src))


def iter_sol_files(root: str) -> List[str]:
    skip = {"node_modules", "lib", ".git", "test", "tests", "mock", "mocks",
            "out", "cache", "script", "scripts"}
    if os.path.isfile(root):
        return [root] if root.endswith(".sol") else []
    found: List[str] = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in skip]
        for n in fn:
            if not n.endswith(".sol") or n.endswith(".t.sol"):
                continue
            if n.startswith("I") and n[1:2].isupper():   # skip interface files
                continue
            found.append(os.path.join(dp, n))
    return sorted(found)


# --------------------------------------------------------------------------- #
# Heuristic patterns
# --------------------------------------------------------------------------- #

_VISIBILITY = {"external", "public", "internal", "private"}
_MUTABILITY = {"view", "pure", "payable"}
_NON_MODIFIER_KW = _VISIBILITY | _MUTABILITY | {
    "returns", "virtual", "override", "function", "memory", "calldata",
    "storage", "immutable", "constant"}

STATE_WRITE = re.compile(
    r"(\b\w+\s*(\+=|-=|\*=|/=)\s)"           # compound assignment
    r"|(\b\w+\[[^\]]*\]\s*=[^=])"            # mapping/array element write
    r"|(\bdelete\s+\w)"                       # delete
    r"|(\.push\s*\()"                         # array push
)
EXTERNAL_CALL = re.compile(
    r"\.call\s*[\({]"
    r"|\.delegatecall\s*\("
    r"|\.staticcall\s*\("
    r"|\.transfer\s*\("
    r"|\.send\s*\("
    r"|\.safeTransfer(From)?\s*\("
    r"|\.transferFrom\s*\("
)
LOWLEVEL_CALL = re.compile(r"\.call\s*[\({]|\.delegatecall\s*\(")
CHECKED_CALL = re.compile(r"\(\s*bool\s+\w+|\brequire\s*\(|=\s*\w+\.call")
ACCESS_MODIFIER = re.compile(r"onlyOwner|onlyRole|onlyAdmin|only[A-Z]\w*|whenNotPaused")
REENTRANCY_GUARD = re.compile(r"nonReentrant|noReentrancy|reentrancyGuard", re.IGNORECASE)

CONTRACT_DECL = re.compile(r"\b(contract|abstract\s+contract|library)\s+([A-Za-z_]\w*)")
MAPPING_BALANCE = re.compile(r"mapping\s*\(\s*address\s*=>\s*uint\d*\s*\)[^;]*(balance|balances|shares|deposits)", re.IGNORECASE)
SUPPLY_VAR = re.compile(r"\buint\d*\b[^;=]*(totalSupply|totalShares|totalDeposits|totalAssets)", re.IGNORECASE)
CONFIG_SETTER = re.compile(r"^(set|update|change|configure|upgrade|migrate|pause|unpause|initialize|grant|revoke|admin|withdrawAll|rescue)", re.IGNORECASE)


@dataclass
class Flag:
    file: str
    line: int
    kind: str
    function: str
    note: str


@dataclass
class Func:
    name: str
    line: int
    visibility: str
    mutability: str
    modifiers: List[str]
    writes_state: bool
    external_call: bool
    entry_point: bool


@dataclass
class FileReport:
    file: str
    contracts: List[str] = field(default_factory=list)
    functions: List[Func] = field(default_factory=list)
    conservation_seed: bool = False
    flags: List[Flag] = field(default_factory=list)


def _line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def _match_paren(src: str, open_idx: int) -> int:
    """Return index just past the matching close paren for the '(' at open_idx."""
    depth = 0
    for i in range(open_idx, len(src)):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(src)


def _match_brace(src: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(src)


def _extract_functions(src: str) -> List[Tuple[str, int, str, str]]:
    """Yield (name, line, signature_attrs, body) for each defined function."""
    out = []
    for m in re.finditer(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", src):
        name = m.group(1)
        line = _line_of(src, m.start())
        paren_open = src.index("(", m.end() - 1)
        params_end = _match_paren(src, paren_open)
        # signature attributes run until the body '{' or a ';' (no body)
        brace = src.find("{", params_end)
        semi = src.find(";", params_end)
        if semi != -1 and (brace == -1 or semi < brace):
            continue  # declaration only (interface/abstract) — no body
        if brace == -1:
            continue
        attrs = src[params_end:brace]
        body_end = _match_brace(src, brace)
        body = src[brace:body_end]
        out.append((name, line, attrs, body))
    return out


_STATE_DECL = re.compile(
    r"(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping\s*\([^;{]*\))\s+"
    r"(?:(?:public|private|internal|external|constant|immutable|override)\s+)*"
    r"([A-Za-z_]\w*)\s*[;=]")


def _state_var_names(src: str) -> set:
    """Collect contract-level state variable names by masking out every function
    body first, so local variables are not mistaken for state."""
    masked = list(src)
    for m in re.finditer(r"\bfunction\s+[A-Za-z_]\w*\s*\(", src):
        paren_open = src.index("(", m.end() - 1)
        params_end = _match_paren(src, paren_open)
        brace = src.find("{", params_end)
        semi = src.find(";", params_end)
        if semi != -1 and (brace == -1 or semi < brace):
            continue
        if brace == -1:
            continue
        body_end = _match_brace(src, brace)
        for i in range(brace, body_end):
            masked[i] = " "
    text = "".join(masked)
    return {m.group(1) for m in _STATE_DECL.finditer(text)}


def _writes_state(body: str, state_vars: set) -> bool:
    if STATE_WRITE.search(body):
        return True
    for name in state_vars:
        esc = re.escape(name)
        if re.search(r"\b" + esc + r"\s*(\+=|-=|\*=|/=|=(?!=))", body):
            return True
        if re.search(r"\b" + esc + r"\s*\[[^\]]*\]\s*=(?!=)", body):
            return True
    return False


def analyze(path: str) -> FileReport:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        src = strip_comments(fh.read())
    rep = FileReport(file=path)
    rep.contracts = [m.group(2) for m in CONTRACT_DECL.finditer(src)]
    rep.conservation_seed = bool(MAPPING_BALANCE.search(src)) and bool(SUPPLY_VAR.search(src))
    state_vars = _state_var_names(src)

    for name, line, attrs, body in _extract_functions(src):
        tokens = re.findall(r"[A-Za-z_]\w*", attrs)
        visibility = next((t for t in tokens if t in _VISIBILITY), "internal")
        mutability = next((t for t in tokens if t in _MUTABILITY), "nonpayable")
        modifiers = [t for t in tokens if t not in _NON_MODIFIER_KW]
        writes = _writes_state(body, state_vars)
        ext = bool(EXTERNAL_CALL.search(body))
        entry = visibility in {"external", "public"} and mutability not in {"view", "pure"}

        rep.functions.append(Func(
            name=name, line=line, visibility=visibility, mutability=mutability,
            modifiers=modifiers, writes_state=writes, external_call=ext,
            entry_point=entry))

        has_access = bool(ACCESS_MODIFIER.search(attrs))
        has_guard = bool(REENTRANCY_GUARD.search(attrs))

        # High-signal: a config/admin-style setter that anyone can call.
        if entry and writes and not has_access and CONFIG_SETTER.match(name):
            rep.flags.append(Flag(
                file=path, line=line, kind="permissionless-config-setter",
                function=name,
                note="a setter/admin-style function writes state with no access modifier — "
                     "anyone can change protocol configuration; confirm intended"))

        # Reentrancy leads focus on caller-open functions that call out.
        if entry and ext and not has_guard and not has_access:
            rep.flags.append(Flag(
                file=path, line=line, kind="external-call-no-reentrancy-guard",
                function=name,
                note="permissionless function makes an external call without a nonReentrant "
                     "guard — verify checks-effects-interactions ordering"))

        # unchecked low-level call
        for lm in LOWLEVEL_CALL.finditer(body):
            seg = body[max(0, lm.start() - 40):lm.start() + 40]
            if not CHECKED_CALL.search(seg):
                rep.flags.append(Flag(
                    file=path, line=line + body[:lm.start()].count("\n"),
                    kind="unchecked-low-level-call", function=name,
                    note="low-level .call/.delegatecall return value may be unchecked — "
                         "confirm the success boolean is handled"))
                break
    return rep


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Enumerate EVM entry points, access control, and invariant seeds.")
    ap.add_argument("path")
    ap.add_argument("--json")
    args = ap.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    reports = [analyze(f) for f in iter_sol_files(args.path)]
    all_funcs = [fn for r in reports for fn in r.functions]
    entry_points = [fn for fn in all_funcs if fn.entry_point]
    permissionless = [fn for fn in entry_points
                      if not any(ACCESS_MODIFIER.search(m) for m in fn.modifiers)]
    all_flags = [asdict(fl) for r in reports for fl in r.flags]

    summary = {
        "root": os.path.abspath(args.path),
        "files_scanned": len(reports),
        "totals": {
            "contracts": sum(len(r.contracts) for r in reports),
            "functions": len(all_funcs),
            "entry_points": len(entry_points),
            "permissionless_entry_points": len(permissionless),
            "conservation_seeds": sum(1 for r in reports if r.conservation_seed),
            "flags": len(all_flags),
        },
        "flags": all_flags,
        "files": [asdict(r) for r in reports if r.functions or r.contracts],
    }

    payload = json.dumps(summary, indent=2)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"wrote {args.json}  ({summary['totals']['entry_points']} entry points, "
              f"{summary['totals']['flags']} flags)")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
