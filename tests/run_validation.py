#!/usr/bin/env python3
"""Regression checks for Skills Agent Skills and deterministic analyzers."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Component:
    name: str
    script: Path
    fixture: Path
    expected_files: int
    expected_flags: int


COMPONENTS = (
    Component(
        "zk-circuit-review",
        ROOT / "zk-circuit-review/scripts/enumerate_circuit.py",
        ROOT / "zk-circuit-review/scripts/fixtures/sample.circom",
        1,
        2,
    ),
    Component(
        "verifier-bridge-audit",
        ROOT / "verifier-bridge-audit/scripts/scan_verifier.py",
        ROOT / "verifier-bridge-audit/scripts/fixtures",
        2,
        3,
    ),
    Component(
        "evm-invariant-scan",
        ROOT / "evm-invariant-scan/scripts/enumerate_evm.py",
        ROOT / "evm-invariant-scan/scripts/fixtures",
        2,
        10,
    ),
)


def run(*args: object, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(arg) for arg in args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"expected exit {expected}, got {result.returncode}: {' '.join(map(str, args))}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def validate_frontmatter(component: Component) -> None:
    skill = ROOT / component.name / "SKILL.md"
    text = skill.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise AssertionError(f"invalid frontmatter delimiters: {skill}")
    header = text.split("---", 2)[1]
    name_match = re.search(r"^name:\s*(.+)$", header, re.MULTILINE)
    description_match = re.search(r'^description:\s*"(.*)"$', header, re.MULTILINE)
    if not name_match or not description_match:
        raise AssertionError(f"missing name or quoted description: {skill}")
    name = name_match.group(1).strip()
    description = description_match.group(1)
    if name != component.name or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        raise AssertionError(f"invalid skill name: {name}")
    if not (1 <= len(name) <= 64 and 1 <= len(description) <= 1024):
        raise AssertionError(f"frontmatter field length violation: {skill}")
    for required in ("license:", "compatibility:", "metadata:", "  author:", "  version:"):
        if required not in header:
            raise AssertionError(f"missing {required} in {skill}")


def validate_agentic_workflow(component: Component) -> None:
    skill_dir = ROOT / component.name
    skill_text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    manifest = json.loads((skill_dir / "skill-manifest.json").read_text(encoding="utf-8"))
    version = (skill_dir / "VERSION").read_text(encoding="utf-8").strip()
    if version != "2.0.0" or manifest.get("version") != version:
        raise AssertionError(f"{component.name}: inconsistent 2.0.0 package version")
    metadata_version = re.search(r'^\s+version:\s+"([^"]+)"$', skill_text, re.MULTILINE)
    if metadata_version is None or metadata_version.group(1) != version:
        raise AssertionError(f"{component.name}: SKILL.md version is inconsistent")
    if manifest.get("risk_tier") != "L2":
        raise AssertionError(f"{component.name}: autonomous workflow must declare L2 risk")
    if "runSubagent" not in manifest.get("permissions", {}).get("tools", []):
        raise AssertionError(f"{component.name}: agent delegation is not declared")

    required_workflow_terms = (
        "## Autonomous execution contract",
        "Independent reasoning lanes",
        "Evidence lattice and challenge",
        "review-ledger.md",
        "Mandatory final report",
        "report.md",
        "E2",
        "E3",
    )
    for term in required_workflow_terms:
        if term not in skill_text:
            raise AssertionError(f"{component.name}: workflow contract missing {term!r}")

    report_text = (skill_dir / "references/report-template.md").read_text(encoding="utf-8")
    for term in (
        "Review-lane coverage",
        "Candidate accounting",
        "Evidence",
        "Completeness declaration",
    ):
        if term not in report_text:
            raise AssertionError(f"{component.name}: report contract missing {term!r}")

    if component.name == "evm-invariant-scan":
        reasoning_text = (skill_dir / "references/reasoning-workflow.md").read_text(encoding="utf-8")
        normalized_reasoning = " ".join(reasoning_text.split())
        for term in ("every read site", "shortest path", "direct consumer path"):
            if term not in normalized_reasoning:
                raise AssertionError(f"{component.name}: sentinel challenge missing {term!r}")


def validate_component(component: Component, output_dir: Path) -> None:
    json_path = output_dir / f"{component.name}.json"
    report_path = output_dir / f"{component.name}.md"
    run(
        sys.executable,
        component.script,
        component.fixture,
        "--json",
        json_path,
        "--report",
        report_path,
        "--no-banner",
    )
    data = json.loads(json_path.read_text(encoding="utf-8"))
    actual = (data["files_scanned"], data["totals"]["flags"])
    expected = (component.expected_files, component.expected_flags)
    if actual != expected:
        raise AssertionError(f"{component.name}: expected files/flags {expected}, got {actual}")

    stdout_run = run(sys.executable, component.script, component.fixture, "--no-banner")
    stdout_data = json.loads(stdout_run.stdout)
    if stdout_data != data:
        raise AssertionError(f"{component.name}: stdout and file JSON differ")

    second_run = run(sys.executable, component.script, component.fixture, "--no-banner")
    if stdout_run.stdout != second_run.stdout:
        raise AssertionError(f"{component.name}: output is not deterministic")

    missing = run(
        sys.executable,
        component.script,
        output_dir / "does-not-exist",
        "--no-banner",
        expected=2,
    )
    if "path not found" not in missing.stderr or "Traceback" in missing.stderr:
        raise AssertionError(f"{component.name}: invalid-path diagnostic is not controlled")


def validate_unwritable_output(output_dir: Path) -> None:
    component = COMPONENTS[-1]
    blocked_parent = output_dir / "blocked"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    result = run(
        sys.executable,
        component.script,
        component.fixture,
        "--json",
        blocked_parent / "result.json",
        "--no-banner",
        expected=2,
    )
    if "failed to write" not in result.stderr or "Traceback" in result.stderr:
        raise AssertionError("output failure is not reported as a controlled diagnostic")


def validate_documentation() -> None:
    markdown_files = (
        sorted(ROOT.glob("*.md"))
        + sorted((ROOT / "docs").glob("*.md"))
        + sorted((ROOT / "examples").rglob("*.md"))
    )
    link_pattern = re.compile(r"\[[^]]*\]\(([^)]+)\)")
    missing_links: list[str] = []
    for document in markdown_files:
        for target in link_pattern.findall(document.read_text(encoding="utf-8")):
            target = target.split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            if not (document.parent / target).resolve().exists():
                missing_links.append(f"{document.relative_to(ROOT)} -> {target}")
    if missing_links:
        raise AssertionError(f"broken relative documentation links: {missing_links}")

    machine_path_pattern = re.compile(r"/home/|/Users/|C:\\\\")
    leaked_paths = []
    for artifact in sorted((ROOT / "examples").rglob("*")):
        if not artifact.is_file() or artifact == ROOT / "examples/README.md":
            continue
        if machine_path_pattern.search(artifact.read_text(encoding="utf-8")):
            leaked_paths.append(str(artifact.relative_to(ROOT)))
    if leaked_paths:
        raise AssertionError(f"machine-specific paths in example artifacts: {leaked_paths}")


def main() -> int:
    for component in COMPONENTS:
        validate_frontmatter(component)
        validate_agentic_workflow(component)
    print("PASS autonomous workflow and report contracts")
    with tempfile.TemporaryDirectory(prefix="skills-") as temp_dir:
        output_dir = Path(temp_dir)
        for component in COMPONENTS:
            validate_component(component, output_dir)
            print(
                f"PASS {component.name}: "
                f"{component.expected_files} files, {component.expected_flags} flags"
            )
        validate_unwritable_output(output_dir)
        print("PASS controlled output failure")
    validate_documentation()
    print("PASS documentation links and publication paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
