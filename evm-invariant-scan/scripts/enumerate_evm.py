#!/usr/bin/env python3
"""
enumerate_evm.py — deterministic entry-point, access-control, and invariant-seed
enumerator for Solidity codebases.

Part of the `evm-invariant-scan` skill.

It builds a reproducible map of a protocol's attack surface without compiling:
  - every contract and its public/external functions,
  - each function's visibility, mutability, access modifiers, and whether it
    writes state or makes an external call,
    - deterministic flags: permissionless state changes, external calls without a
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
from datetime import datetime, timezone
from typing import List, Tuple


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
    "unprotected-upgrade": "Critical",
    "permissionless-config-setter": "High",
    "external-call-no-reentrancy-guard": "High",
    "spot-price-oracle": "High",
    "balance-based-accounting": "High",
    "initializer-not-guarded": "High",
    "selfdestruct-present": "High",
    "oracle-deprecated-feed": "Medium",
    "oracle-missing-staleness-check": "Medium",
    "flash-loan-callback": "Medium",
    "unchecked-low-level-call": "Medium",
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
    """Render the normative markdown summary for an EVM enumeration result."""
    t = summary["totals"]
    root = os.path.basename(summary["root"].rstrip("/")) or summary["root"]
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    flags = summary["flags"]

    L: List[str] = []
    L.append(f"# EVM Invariant Scan — {root}")
    L.append("")
    L.append(f"> VLDMR Skills · `evm-invariant-scan` v{_read_version()} · {date} (UTC)")
    L.append("")
    L.append(f"**Scope:** `{summary['root']}` · {summary['files_scanned']} Solidity file(s)")
    L.append("")
    L.append("## Summary")
    L.append("")
    L.append("| metric | value |")
    L.append("| --- | ---: |")
    L.append(f"| Contracts | {t['contracts']} |")
    L.append(f"| Functions | {t['functions']} |")
    L.append(f"| Entry points (external/public) | {t['entry_points']} |")
    L.append(f"| Permissionless entry points | {t['permissionless_entry_points']} |")
    L.append(f"| Conservation seeds (supply vs. balances) | {t['conservation_seeds']} |")
    L.append(f"| **Flags** | **{t['flags']}** |")
    L.append("")

    L.append("## Entry-point and access map")
    L.append("")
    L.append("| Source / function | Visibility | Access indicators | Writes state | External call |")
    L.append("| --- | --- | --- | :---: | :---: |")
    entry_points = []
    for file_report in summary.get("files", []):
        source = os.path.basename(file_report["file"])
        for function in file_report.get("functions", []):
            if function.get("entry_point"):
                entry_points.append((source, function))
    if entry_points:
        for source, function in entry_points:
            modifiers = ", ".join(function.get("modifiers") or []) or "none detected"
            writes = "yes" if function.get("writes_state") else "no"
            external = "yes" if function.get("external_call") else "no"
            L.append(f"| `{source} / {function['name']}` | {function['visibility']} | "
                     f"{modifiers} | {writes} | {external} |")
    else:
        L.append("| _(no state-changing public or external entry points enumerated)_ | — | — | — | — |")
    L.append("")

    L.append("## Analysis observations")
    L.append("")
    if not flags:
        L.append("No implemented access-control, external-call, oracle, flash-loan, or "
                 "upgradeability detection pattern matched the analyzed source. Derived "
                 "invariants require implementation and execution in a verification tool.")
    else:
        L.append("The following static-analysis observations require source-level and "
                 "state-transition verification before classification as findings.")
        L.append("")
        L.append("| # | Severity | Kind | Function | Location | Note |")
        L.append("| ---: | --- | --- | --- | --- | --- |")
        for i, f in enumerate(flags, 1):
            sev = _SEVERITY.get(f["kind"], "Unrated")
            fn = f.get("function") or "—"
            loc = f"{os.path.basename(f['file'])}:{f['line']}"
            L.append(f"| {i} | {sev} | `{f['kind']}` | `{fn}` | {loc} | {f['note']} |")
    L.append("")
    L.append("## Invariant seeds")
    L.append("")
    L.append("Suggested properties to encode for fuzzing / formal review:")
    L.append("")
    L.append(f"- **Access control:** {t['permissionless_entry_points']} permissionless entry "
             "point(s) — confirm each is intentionally public.")
    if t["conservation_seeds"]:
        L.append(f"- **Value conservation:** {t['conservation_seeds']} contract(s) track a "
                 "supply/total against per-account balances — assert sum(balances) == total.")
    L.append("- **Monotonicity / solvency:** encode any documented \"never decreases\" or "
             "\"assets ≥ liabilities\" property as an Echidna/Medusa invariant.")
    L.append("")
    L.append("## Analysis status")
    L.append("")
    L.append(_verdict(flags))
    L.append("")
    L.append("## Method & limits")
    L.append("")
    L.append("- Deterministic regex over comment-stripped Solidity (no compile, no network).")
    L.append("- Flags identify structural source patterns. Classification requires manual "
             "review and, where applicable, executable verification.")
    return "\n".join(L) + "\n"


def _verdict(flags: List[dict]) -> str:
    if not flags:
        return ("**NO FLAGS.** No implemented access-control, external-call, oracle, "
                "flash-loan, or upgradeability detection pattern matched the analyzed source.")
    crit = [f for f in flags if _SEVERITY.get(f["kind"]) in {"Critical", "High"}]
    if crit:
        return (f"**REVIEW REQUIRED.** {len(crit)} observation(s) are mapped to "
                "high-impact EVM risk classes and require manual verification.")
    return (f"**REVIEW REQUIRED.** {len(flags)} observation(s) require manual "
        "verification and disposition.")



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
# Inline authorization inside the body: `require(msg.sender == owner)`,
# `if (msg.sender != admin) revert ...`, etc. Common in codebases that avoid
# modifiers (e.g. Uniswap v4). Treated as equivalent to an access modifier.
INLINE_AUTH = re.compile(
    r"require\s*\(\s*msg\.sender\s*==|"
    r"if\s*\(\s*msg\.sender\s*[!=]=[^)]*\)[^;{]*revert|"
    r"_checkOwner\s*\(|_checkRole\s*\(")
REENTRANCY_GUARD = re.compile(r"nonReentrant|noReentrancy|reentrancyGuard", re.IGNORECASE)

CONTRACT_DECL = re.compile(r"\b(contract|abstract\s+contract|library)\s+([A-Za-z_]\w*)")
MAPPING_BALANCE = re.compile(r"mapping\s*\(\s*address\s*=>\s*uint\d*\s*\)[^;]*(balance|balances|shares|deposits)", re.IGNORECASE)
SUPPLY_VAR = re.compile(r"\buint\d*\b[^;=]*(totalSupply|totalShares|totalDeposits|totalAssets)", re.IGNORECASE)
CONFIG_SETTER = re.compile(r"^(set|update|change|configure|upgrade|migrate|pause|unpause|initialize|grant|revoke|admin|withdrawAll|rescue)", re.IGNORECASE)

# --- OWASP Smart Contract Top 10 (2026) coverage extensions ----------------- #
# SC03 — price-oracle manipulation.
SPOT_ORACLE = re.compile(
    r"\.getReserves\s*\(|\.slot0\s*\(|\.getAmountsOut\s*\(|"
    r"\.price0CumulativeLast\b|\.price1CumulativeLast\b")
CHAINLINK_ROUND = re.compile(r"latestRoundData\s*\(")
CHAINLINK_STALE = re.compile(r"updatedAt|answeredInRound")
CHAINLINK_DEPRECATED = re.compile(r"\.latestAnswer\s*\(|\.latestRound\s*\(")

# SC04 — flash-loan-facilitated attacks.
FLASHLOAN_CALLBACKS = {
    "onFlashLoan", "receiveFlashLoan", "executeOperation", "uniswapV2Call",
    "pancakeCall", "uniswapV3FlashCallback", "flashCallback", "DPPFlashLoanCall",
    "BEP20FlashLoanCall", "callFunction",
}
SELF_BALANCE = re.compile(
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|"
    r"\baddress\s*\(\s*this\s*\)\s*\.balance\b|\bselfbalance\s*\(")

# SC10 — proxy / upgradeability.
UPGRADE_FNS = {"upgradeTo", "upgradeToAndCall", "_authorizeUpgrade"}
INIT_FN = re.compile(r"^(initialize|init|__\w+_init)$")
INITIALIZER_MODS = re.compile(r"\binitializer\b|\breinitializer\s*\(")
# An unguarded `initialize` is only an ownership-takeover risk in an
# upgradeable/proxy context. `initialize(...)` on a plain contract (e.g. pool
# creation in a DEX) is a legitimate permissionless action.
_PROXY_CONTEXT = re.compile(
    r"\bInitializable\b|\bUUPSUpgradeable\b|\bupgradeTo|\bproxiableUUID\b|"
    r"\bdelegateInit\b|\b__gap\b|\bERC1967\b|\b_authorizeUpgrade\b", re.IGNORECASE)
SELFDESTRUCT = re.compile(r"\bselfdestruct\s*\(|\bsuicide\s*\(")


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

        has_access = bool(ACCESS_MODIFIER.search(attrs)) or bool(INLINE_AUTH.search(body))
        has_guard = bool(REENTRANCY_GUARD.search(attrs))
        has_init_guard = bool(INITIALIZER_MODS.search(attrs))

        # High-signal: a configuration setter without recognized authorization.
        # An `initializer`/`reinitializer` modifier is a one-shot guard, so a
        # guarded initializer is not a permissionless setter.
        if entry and writes and not has_access and not has_init_guard and CONFIG_SETTER.match(name):
            rep.flags.append(Flag(
                file=path, line=line, kind="permissionless-config-setter",
                function=name,
                 note="a configuration function writes state without a recognized access "
                     "modifier or inline authorization check"))

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

        # SC03 — price-oracle manipulation leads.
        if SPOT_ORACLE.search(body):
            rep.flags.append(Flag(
                file=path, line=line, kind="spot-price-oracle", function=name,
                note="reads an AMM spot price (getReserves/slot0/getAmountsOut) — spot prices "
                     "are manipulable within a block via flash loans; prefer a TWAP or a "
                     "validated Chainlink feed (OWASP SC03)"))
        if CHAINLINK_DEPRECATED.search(body):
            rep.flags.append(Flag(
                file=path, line=line, kind="oracle-deprecated-feed", function=name,
                note="uses latestAnswer()/latestRound() — deprecated Chainlink API with no "
                     "round/staleness data; use latestRoundData() and validate it (OWASP SC03)"))
        elif CHAINLINK_ROUND.search(body) and not CHAINLINK_STALE.search(body):
            rep.flags.append(Flag(
                file=path, line=line, kind="oracle-missing-staleness-check", function=name,
                note="calls latestRoundData() without checking updatedAt/answeredInRound — a "
                     "stale price may be accepted (OWASP SC03)"))

        # SC04 — flash-loan-facilitated attack leads.
        if name in FLASHLOAN_CALLBACKS:
            rep.flags.append(Flag(
                file=path, line=line, kind="flash-loan-callback", function=name,
                note="flash-loan callback — verify caller/initiator authentication and that no "
                     "price/share math inside can be manipulated mid-callback (OWASP SC04)"))
        if SELF_BALANCE.search(body) and "/" in body:
            rep.flags.append(Flag(
                file=path, line=line, kind="balance-based-accounting", function=name,
                note="derives a value from the contract's own live balance and divides — share/"
                     "price math from balanceOf(this) is inflatable by a donation or flash loan; "
                     "track accounted balances instead (OWASP SC04)"))

        # SC10 — proxy / upgradeability leads.
        if name in UPGRADE_FNS and not has_access and not ACCESS_MODIFIER.search(body):
            rep.flags.append(Flag(
                file=path, line=line, kind="unprotected-upgrade", function=name,
                note="upgrade authorization path has no visible access control — confirm only "
                     "governance/owner can upgrade the implementation (OWASP SC10)"))
        if (INIT_FN.match(name) and entry and not has_init_guard
                and _PROXY_CONTEXT.search(src)):
            rep.flags.append(Flag(
                file=path, line=line, kind="initializer-not-guarded", function=name,
                note="initializer-style function without an `initializer`/`reinitializer` "
                     "modifier — may be callable again to re-take ownership (OWASP SC10)"))

    # SC10 — self-destruct present anywhere in the file.
    sd = SELFDESTRUCT.search(src)
    if sd:
        rep.flags.append(Flag(
            file=path, line=_line_of(src, sd.start()), kind="selfdestruct-present",
            function="(file)",
            note="selfdestruct/suicide present — in a proxy or shared contract this can brick "
                 "the implementation or drain funds; confirm it is unreachable by untrusted "
                 "callers (OWASP SC10)"))
    return rep


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Enumerate EVM entry points, access control, and invariant seeds.")
    ap.add_argument("path")
    ap.add_argument("--json")
    ap.add_argument("--report", help="write a markdown scan report to this path")
    ap.add_argument("--no-banner", action="store_true", help="suppress the banner")
    args = ap.parse_args(argv)

    if not args.no_banner:
        _print_banner("evm-invariant-scan · entry points, access control & invariants")

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

    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(build_report(summary))
        print(f"wrote {args.report}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
