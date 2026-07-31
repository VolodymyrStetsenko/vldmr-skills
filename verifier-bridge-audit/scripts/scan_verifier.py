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
from datetime import datetime, timezone
from typing import List


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
    "possible-proof-replay": "Critical",
    "unbound-public-inputs": "High",
    "mutable-verifier": "High",
}


def _print_banner(subtitle: str) -> None:
    """Print the VLDMR Skills banner to stderr (stdout stays machine-readable)."""
    print(_BANNER, file=sys.stderr)
    print(f"  VLDMR Skills · {subtitle}\n", file=sys.stderr)


def _read_version() -> str:
    try:
        with open(os.path.join(os.path.dirname(__file__), "..", "VERSION")) as fh:
            return fh.read().strip()
    except OSError:
        return "?"


def build_report(summary: dict) -> str:
    """Render a professional, minimalist markdown report from the JSON summary."""
    t = summary["totals"]
    root = os.path.basename(summary["root"].rstrip("/")) or summary["root"]
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    flags = summary["flags"]

    L: List[str] = []
    L.append(f"# Verifier Bridge Audit — {root}")
    L.append("")
    L.append(f"> VLDMR Skills · `verifier-bridge-audit` v{_read_version()} · {date} (UTC)")
    L.append("")
    L.append(f"**Scope:** `{summary['root']}` · {summary['files_scanned']} Solidity file(s)")
    L.append("")
    L.append("## Summary")
    L.append("")
    L.append("| metric | value |")
    L.append("| --- | ---: |")
    L.append(f"| Proof-verifier contracts | {t['verifiers']} |")
    L.append(f"| Verifier consumers | {t['consumers']} |")
    L.append(f"| Verification call sites | {t['verification_call_sites']} |")
    L.append(f"| **Leads** | **{t['flags']}** |")
    L.append("")

    verifiers = summary.get("verifier_contracts") or []
    consumers = summary.get("consumer_contracts") or []
    if verifiers:
        L.append("**Verifiers:** " + ", ".join(f"`{os.path.basename(v)}`" for v in verifiers))
        L.append("")
    if consumers:
        L.append("**Consumers:** " + ", ".join(f"`{os.path.basename(c)}`" for c in consumers))
        L.append("")

    L.append("## Integration guardrails")
    L.append("")
    L.append("For each verifier consumer, three classic ZK-EVM protections are checked.")
    L.append("")
    L.append("| Consumer | Replay/nullifier guard | Public-input binding |")
    L.append("| --- | :---: | :---: |")
    any_consumer = False
    for fr in summary.get("files", []):
        if not fr.get("consumer_calls"):
            continue
        any_consumer = True
        guard = "yes" if (fr.get("has_nullifier_tracking") and fr.get("has_replay_guard")) else "**no**"
        bind = "yes" if fr.get("binds_context") else "**no**"
        L.append(f"| `{os.path.basename(fr['file'])}` | {guard} | {bind} |")
    if not any_consumer:
        L.append("| _(no verifier consumers found)_ | — | — |")
    L.append("")

    L.append("## Leads")
    L.append("")
    if not flags:
        L.append("No integration leads. Every verifier consumer this scanner can see has "
                 "replay tracking and binds public inputs to context. Confirm the binding "
                 "actually covers the recipient/scope your protocol relies on.")
    else:
        L.append("Each row is a **lead** to confirm against the real data flow, not a finding.")
        L.append("")
        L.append("| # | Severity | Kind | Location | Note |")
        L.append("| ---: | --- | --- | --- | --- |")
        for i, f in enumerate(flags, 1):
            sev = _SEVERITY.get(f["kind"], "Lead")
            loc = f"{os.path.basename(f['file'])}:{f['line']}"
            L.append(f"| {i} | {sev} | `{f['kind']}` | {loc} | {f['note']} |")
    L.append("")
    L.append("## Verdict")
    L.append("")
    L.append(_verdict(flags))
    L.append("")
    L.append("## Method & limits")
    L.append("")
    L.append("- Deterministic regex over comment-stripped Solidity (no compile, no network).")
    L.append("- Binding is inferred from the *arguments* passed to `verifyProof`; a consumer "
             "may still bind context in a way this scanner cannot see — confirm manually.")
    L.append("- Verifier detection covers Groth16/PLONK templates and optimized Yul verifiers; "
             "exotic custom verifiers may be missed.")
    return "\n".join(L) + "\n"


def _verdict(flags: List[dict]) -> str:
    if not flags:
        return ("**Clean surface.** No replay, unbound-input, or mutable-verifier leads were "
                "detected across verifier consumers.")
    crit = [f for f in flags if _SEVERITY.get(f["kind"]) in {"Critical", "High"}]
    if crit:
        return (f"**Review required.** {len(crit)} high-severity integration lead(s) "
                "(replay / unbound public inputs / mutable verifier). Confirm before deployment.")
    return f"**Leads to confirm.** {len(flags)} lead(s) to review."



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

# A file is a *verifier* if it looks like a generated or hand-written proof
# checker. Two families are covered: (a) the classic snarkjs / hand-written
# Solidity templates that reference the bn254 scalar field and a `Pairing`
# library, and (b) modern optimized Yul verifiers (snarkjs >=0.7, Semaphore's
# SemaphoreVerifier) that inline the precompile calls with decimal ids.
VERIFIER_MARKERS = [
    re.compile(r"\bfunction\s+verifyProof\s*\("),
    re.compile(r"\bfunction\s+verify\s*\([^)]*proof", re.IGNORECASE),
    re.compile(r"\bPairing\b"),
    re.compile(r"\bscalar_field\b|\bsnark_scalar_field\b"),
    re.compile(r"\bstaticcall\s*\(\s*sub\s*\(\s*gas|0x08\b"),    # pairing precompile (hex id)
    re.compile(r"\bstaticcall\s*\([^,;{]*,\s*8\s*,"),            # pairing precompile (decimal id 8)
    re.compile(r"\bstaticcall\s*\([^,;{]*,\s*[67]\s*,"),         # ecAdd(6) / ecMul(7) precompiles
    re.compile(r"\bpPairing\b|\bcheckPairing\b"),               # optimized Yul verifier idioms
    re.compile(r"\bvk\.\w+|\bVerifyingKey\b|\balphax?1\b|\bgamma2\b|\bdelta2\b", re.IGNORECASE),
]

# A *consumer* call site invokes a verifier.
CONSUMER_CALL = re.compile(r"\b(\w+)\s*\.\s*(verifyProof|verify)\s*\(")
INTERNAL_VERIFY = re.compile(r"\b(verifyProof|_verifyProof)\s*\(")

# Replay / nullifier tracking near a consumption site.
NULLIFIER_MARKERS = re.compile(
    r"nullifier|nullifierHash|usedProof|proofUsed|_used\b|spent|isSpent|"
    r"consumed|commitments?\[", re.IGNORECASE)

# A replay guard exists if the code rejects a previously-seen proof/nullifier or
# marks it consumed. We accept the several idioms seen in production verifiers,
# not only `require(!used[x])`:
#   - require(!used[x])                              (boolean-map negation)
#   - revert AlreadyUsed() / ...Twice / ...Spent     (custom errors)
#   - if (nullifiers[x]) revert / require            (conditional revert)
#   - nullifiers[x] = true  /  .nullifiers[x] = true (mark consumed)
REPLAY_GUARD_PATTERNS = [
    re.compile(r"require\s*\(\s*!"),
    re.compile(r"revert\s+\w*(Already|Used|Spent|Twice|Duplicate|Replay|Known|Seen)", re.IGNORECASE),
    re.compile(r"if\s*\([^)]*(nullifier|nullifierhash|used|spent|consumed|commitment|known|seen)[^)]*\)\s*\{?\s*(revert|require)", re.IGNORECASE),
    re.compile(r"(nullifier|nullifierhash|used|spent|consumed|commitment)\w*\s*\[[^\]]*\]\s*=\s*true", re.IGNORECASE),
    re.compile(r"\.\s*(nullifiers?|used|spent|consumed|commitments?)\s*\[[^\]]*\]\s*=\s*true", re.IGNORECASE),
]

# Proof-to-context binding. A proof is safely bound if its *public inputs* commit
# to caller/recipient/scope/domain data, so it cannot be replayed by or
# front-run for a different actor. We look for these terms (a) inside the public
# arguments actually passed to the verify call, and (b) as an explicit
# msg.sender check in the enclosing function body.
MSG_SENDER = re.compile(r"\bmsg\.sender\b")
BINDING_TERMS = re.compile(
    r"\bmsg\.sender\b|\bnullifier|\bscope\b|\bexternalNullifier\b|\bsignalHash\b|"
    r"\brecipient\b|\breceiver\b|\bdomainSeparator\b|\bdomain\b|\bchainid\b|"
    r"address\s*\(\s*this\s*\)", re.IGNORECASE)

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
    args: str = ""


@dataclass
class FileReport:
    file: str
    is_verifier: bool = False
    consumer_calls: List[CallSite] = field(default_factory=list)
    has_nullifier_tracking: bool = False
    has_replay_guard: bool = False
    binds_context: bool = False
    verifier_settable: bool = False
    verifier_immutable: bool = False
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
    call_args: List[str] = []
    for m in CONSUMER_CALL.finditer(src):
        recv = m.group(1)
        if recv in {"this", "super"}:
            continue
        paren_open = src.index("(", m.end() - 1)
        args = src[paren_open:_match_paren(src, paren_open)]
        call_indices.append(m.start())
        call_args.append(args)
        rep.consumer_calls.append(
            CallSite(file=path, line=_line_of(src, m.start()),
                     receiver=recv, method=m.group(2), args=args))

    rep.has_nullifier_tracking = bool(NULLIFIER_MARKERS.search(src))
    rep.has_replay_guard = any(p.search(src) for p in REPLAY_GUARD_PATTERNS)
    rep.verifier_settable = bool(SETTER.search(src))
    rep.verifier_immutable = bool(IMMUTABLE_VK.search(src))

    # Proof-to-context binding is only meaningful *on the verification path*.
    # A proof is bound if its public-input arguments commit to caller/recipient/
    # scope/domain data, or the enclosing function explicitly checks msg.sender.
    # A term merely appearing elsewhere in the body (e.g. a `recipient` parameter
    # that is NOT passed into the proof) does not count — we require it inside
    # the verify call's arguments.
    for args in call_args:
        if BINDING_TERMS.search(args):
            rep.binds_context = True
            break
    if not rep.binds_context:
        for idx in call_indices:
            if MSG_SENDER.search(_enclosing_body(src, idx)):
                rep.binds_context = True
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

        if not rep.binds_context:
            rep.flags.append(Flag(
                file=path, line=first_line, kind="unbound-public-inputs",
                note=("the proof's public inputs do not appear to commit to caller/"
                      "recipient/scope/domain data (no msg.sender, nullifier, scope, "
                      "recipient or domain-separator on the verification path) — a valid "
                      "proof may be front-run or reused by another actor; confirm the "
                      "binding.")))

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
    ap.add_argument("--report", help="write a markdown audit report to this path")
    ap.add_argument("--no-banner", action="store_true", help="suppress the banner")
    args = ap.parse_args(argv)

    if not args.no_banner:
        _print_banner("verifier-bridge-audit · on-chain proof integration")

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

    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(build_report(summary))
        print(f"wrote {args.report}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
