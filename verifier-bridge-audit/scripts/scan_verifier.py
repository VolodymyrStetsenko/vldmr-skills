#!/usr/bin/env python3
"""
scan_verifier.py — static locator for on-chain proof verifiers and the contracts
that consume them.

Part of the `verifier-bridge-audit` skill.

It answers three questions about a Solidity codebase, deterministically:
  1. Which contracts are proof verifiers (Groth16 / PLONK / custom pairing)?
  2. Which contracts consume a verifier (call `verify` / `verifyProof`)?
  3. At each consumption site, are the classic ZK-EVM integration protections
     present — replay/nullifier tracking, public-input-to-state binding, and a
     trustworthy verifying-key source?

No compilation, no network. Regex over comment-stripped source. Every flag is a
lead for a human/agent to confirm against the real data flow.

Usage:
  scan_verifier.py <path> [--json OUT]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import List


_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")


def strip_comments(src: str) -> str:
    def _block_repl(m: re.Match) -> str:
        return "\n" * m.group(0).count("\n")
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub(_block_repl, src))


def iter_sol_files(root: str) -> List[str]:
    skip = {"node_modules", "lib", ".git", "test", "tests", "mock", "mocks", "out", "cache"}
    if os.path.isfile(root):
        return [root] if root.endswith(".sol") else []
    found: List[str] = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in skip]
        for n in fn:
            if n.endswith(".sol") and not n.endswith(".t.sol"):
                found.append(os.path.join(dp, n))
    return sorted(found)


# --------------------------------------------------------------------------- #
# Signal patterns
# --------------------------------------------------------------------------- #

# A file is a *verifier* if it looks like a generated or hand-written proof checker.
VERIFIER_MARKERS = [
    re.compile(r"\bfunction\s+verifyProof\s*\("),
    re.compile(r"\bfunction\s+verify\s*\([^)]*proof", re.IGNORECASE),
    re.compile(r"\bPairing\b"),
    re.compile(r"\bscalar_field\b|\bsnark_scalar_field\b"),
    re.compile(r"\bstaticcall\s*\(\s*sub\s*\(\s*gas|0x08\b"),   # bn254 pairing precompile
    re.compile(r"\bvk\.\w+|\bVerifyingKey\b|\balphax?1\b|\bgamma2\b|\bdelta2\b", re.IGNORECASE),
]

# A *consumer* call site invokes a verifier.
CONSUMER_CALL = re.compile(r"\b(\w+)\s*\.\s*(verifyProof|verify)\s*\(")
INTERNAL_VERIFY = re.compile(r"\b(verifyProof|_verifyProof)\s*\(")

# Replay / nullifier tracking near a consumption site.
NULLIFIER_MARKERS = re.compile(
    r"nullifier|nullifierHash|usedProof|proofUsed|_used\b|spent|isSpent|"
    r"consumed|commitments?\[", re.IGNORECASE)
REPLAY_GUARD = re.compile(
    r"require\s*\(\s*!|revert\s+\w*Already|revert\s+\w*Used|revert\s+\w*Spent", re.IGNORECASE)

# Public-input-to-caller binding.
MSG_SENDER = re.compile(r"\bmsg\.sender\b")
PUBLIC_INPUT_ARR = re.compile(r"\b(uint256|uint)\s*\[\s*\d*\s*\]\s*(memory\s+)?\w*input", re.IGNORECASE)

# Verifying-key / verifier-address mutability.
SETTER = re.compile(r"\bfunction\s+set\w*(Verifier|VerifyingKey|VK)\w*\s*\(", re.IGNORECASE)
IMMUTABLE_VK = re.compile(r"\b(immutable|constant)\b[^;]*verif", re.IGNORECASE)


@dataclass
class Flag:
    file: str
    line: int
    kind: str
    note: str


@dataclass
class CallSite:
    file: str
    line: int
    receiver: str
    method: str


@dataclass
class FileReport:
    file: str
    is_verifier: bool = False
    consumer_calls: List[CallSite] = field(default_factory=list)
    has_nullifier_tracking: bool = False
    has_replay_guard: bool = False
    binds_msg_sender: bool = False
    verifier_settable: bool = False
    verifier_immutable: bool = False
    flags: List[Flag] = field(default_factory=list)


def _line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def _enclosing_body(src: str, idx: int) -> str:
    """Return the source of the function body that contains character `idx`,
    resolved by brace matching so neighbouring functions cannot leak in."""
    fpos = src.rfind("function", 0, idx)
    if fpos == -1:
        return ""
    bstart = src.find("{", fpos)
    if bstart == -1:
        return ""
    depth = 0
    for i in range(bstart, len(src)):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[bstart:i + 1]
    return src[bstart:]


def analyze(path: str) -> FileReport:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    src = strip_comments(raw)
    rep = FileReport(file=path)

    rep.is_verifier = sum(1 for p in VERIFIER_MARKERS if p.search(src)) >= 2

    call_indices: List[int] = []
    for m in CONSUMER_CALL.finditer(src):
        recv = m.group(1)
        if recv in {"this", "super"}:
            continue
        call_indices.append(m.start())
        rep.consumer_calls.append(
            CallSite(file=path, line=_line_of(src, m.start()),
                     receiver=recv, method=m.group(2)))

    rep.has_nullifier_tracking = bool(NULLIFIER_MARKERS.search(src))
    rep.has_replay_guard = bool(REPLAY_GUARD.search(src))
    rep.verifier_settable = bool(SETTER.search(src))
    rep.verifier_immutable = bool(IMMUTABLE_VK.search(src))

    # Public-input binding is only meaningful *on the verification path*, so we
    # inspect the enclosing function body of each verification call rather than
    # the whole file (an unrelated `onlyOwner` check must not mask a missing
    # binding in `withdraw`).
    for idx in call_indices:
        if MSG_SENDER.search(_enclosing_body(src, idx)):
            rep.binds_msg_sender = True
            break

    # --- Flags: only meaningful on consumer contracts (not pure verifiers) --- #
    if rep.consumer_calls and not rep.is_verifier:
        first_line = rep.consumer_calls[0].line

        if not (rep.has_nullifier_tracking and rep.has_replay_guard):
            rep.flags.append(Flag(
                file=path, line=first_line, kind="possible-proof-replay",
                note=("verifier is invoked but no nullifier tracking + reject-if-used "
                      "guard was found in this file — a valid proof may be replayable. "
                      "Confirm where the proof/nullifier is marked consumed.")))

        if not rep.binds_msg_sender:
            rep.flags.append(Flag(
                file=path, line=first_line, kind="unbound-public-inputs",
                note=("no reference to msg.sender near the verification path — confirm "
                      "the public inputs bind the proof to the intended caller/recipient, "
                      "otherwise a proof can be front-run or reused by another actor.")))

        if rep.verifier_settable and not rep.verifier_immutable:
            m = SETTER.search(src)
            rep.flags.append(Flag(
                file=path, line=_line_of(src, m.start()), kind="mutable-verifier",
                note=("the verifier / verifying key is settable — confirm the setter is "
                      "guarded (timelock or governance), else a compromised admin can "
                      "swap in a verifier that accepts forged proofs.")))

    return rep


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Locate on-chain proof verifiers and audit their consumers.")
    ap.add_argument("path")
    ap.add_argument("--json")
    args = ap.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    reports = [analyze(f) for f in iter_sol_files(args.path)]
    verifiers = [r.file for r in reports if r.is_verifier]
    consumers = [r for r in reports if r.consumer_calls and not r.is_verifier]
    all_flags = [asdict(fl) for r in reports for fl in r.flags]

    summary = {
        "root": os.path.abspath(args.path),
        "files_scanned": len(reports),
        "verifier_contracts": verifiers,
        "consumer_contracts": [r.file for r in consumers],
        "totals": {
            "verifiers": len(verifiers),
            "consumers": len(consumers),
            "verification_call_sites": sum(len(r.consumer_calls) for r in reports),
            "flags": len(all_flags),
        },
        "flags": all_flags,
        "files": [asdict(r) for r in reports if r.is_verifier or r.consumer_calls],
    }

    payload = json.dumps(summary, indent=2)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"wrote {args.json}  ({summary['totals']['verifiers']} verifiers, "
              f"{summary['totals']['consumers']} consumers, "
              f"{summary['totals']['flags']} flags)")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
