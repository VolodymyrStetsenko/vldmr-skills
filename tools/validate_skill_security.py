#!/usr/bin/env python3
"""Validate VLDMR skill packages against their declared security contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "skill-manifest.json"
SCHEMA_VERSION = "vldmr.skill-security.v1"
SKILL_NAMES = (
    "zk-circuit-review",
    "verifier-bridge-audit",
    "evm-invariant-scan",
)
IDENTITY_FILES = {"AGENTS.md", "MEMORY.md", "SOUL.md"}
IGNORED_PARTS = {"__pycache__", ".DS_Store"}
FORBIDDEN_SUFFIXES = {
    ".7z",
    ".class",
    ".dll",
    ".docm",
    ".docx",
    ".dylib",
    ".exe",
    ".jar",
    ".o",
    ".pdf",
    ".pyc",
    ".so",
    ".tar",
    ".tgz",
    ".whl",
    ".xlsm",
    ".xlsx",
    ".zip",
}
MAX_TEXT_BYTES = 2_000_000
TEXT_SUFFIXES = {"", ".circom", ".json", ".md", ".nr", ".py", ".rs", ".sol", ".txt"}
URL_RE = re.compile(r"https?://[^\s)\]}>\"']+")
ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
UNSAFE_YAML_RE = re.compile(r"!!(?:python|ruby|js)/|!!python/(?:object|apply|name)", re.IGNORECASE)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])")
NETWORK_CODE_RE = re.compile(
    r"\b(?:import|from)\s+(?:http|requests|socket|urllib)\b|"
    r"\b(?:curl|wget)\b|https?://",
    re.IGNORECASE,
)
PROCESS_CODE_RE = re.compile(
    r"\b(?:os\.system|subprocess\.(?:call|check_call|check_output|Popen|run))\s*\(",
)
DYNAMIC_CODE_RE = re.compile(r"\b(?:eval|exec)\s*\(")
SKILL_NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
SEMVER_RE = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)")
SKILL_FRONTMATTER_KEYS = {
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
    "allowed-tools",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    path: str
    line: int | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
        }
        if self.line is not None:
            result["line"] = self.line
        return result


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    if path.is_symlink():
        return _sha256(f"symlink:{os.readlink(path)}".encode())
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _payload_files(skill_dir: Path) -> list[Path]:
    files = []
    for path in skill_dir.rglob("*"):
        if (not path.is_file() and not path.is_symlink()) or path.name == MANIFEST_NAME:
            continue
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        files.append(path)
    return sorted(files, key=lambda path: path.relative_to(skill_dir).as_posix())


def _payload_hashes(skill_dir: Path) -> dict[str, str]:
    return {
        path.relative_to(skill_dir).as_posix(): _sha256_path(path)
        for path in _payload_files(skill_dir)
    }


def _content_hash(file_hashes: dict[str, str]) -> str:
    canonical = json.dumps(file_hashes, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{_sha256(canonical)}"


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _finding(
    findings: list[Finding],
    rule_id: str,
    severity: str,
    message: str,
    path: str,
    line: int | None = None,
) -> None:
    findings.append(Finding(rule_id, severity, message, path, line))


def _require_keys(
    data: dict[str, Any],
    required: set[str],
    allowed: set[str],
    path: str,
    findings: list[Finding],
) -> None:
    for key in sorted(required - data.keys()):
        _finding(findings, "AST04", "high", f"missing required field: {key}", path)
    for key in sorted(data.keys() - allowed):
        _finding(findings, "AST04", "high", f"undeclared schema field: {key}", path)


def _string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def _frontmatter_scalar(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return None
        return decoded if isinstance(decoded, str) else None
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            return None
        return value[1:-1].replace("''", "'")
    if any(token in value for token in (" #", "{", "}", "[", "]", "&", "*", "!", "|", ">")):
        return None
    return value


def _parse_skill_frontmatter(text: str) -> tuple[dict[str, Any] | None, str | None]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return None, "SKILL.md must start with YAML frontmatter"
    try:
        closing = lines.index("---", 1)
    except ValueError:
        return None, "SKILL.md frontmatter is not closed"

    result: dict[str, Any] = {}
    current_map: dict[str, str] | None = None
    for line in lines[1:closing]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[:indent] or ":" not in line:
            return None, "SKILL.md frontmatter contains unsupported YAML"
        key, raw_value = line.strip().split(":", 1)
        if indent:
            if current_map is None or not key or key in current_map:
                return None, "SKILL.md metadata must be a flat string map"
            value = _frontmatter_scalar(raw_value)
            if value is None:
                return None, "SKILL.md metadata values must be non-empty strings"
            current_map[key] = value
            continue
        if not key or key in result:
            return None, "SKILL.md frontmatter keys must be unique"
        if key == "metadata" and not raw_value.strip():
            current_map = {}
            result[key] = current_map
            continue
        current_map = None
        value = _frontmatter_scalar(raw_value)
        if value is None:
            return None, f"SKILL.md field {key} must be a non-empty string"
        result[key] = value
    return result, None


def _validate_skill_frontmatter(skill_name: str, text: str, findings: list[Finding]) -> None:
    skill_path = f"{skill_name}/SKILL.md"
    frontmatter, error = _parse_skill_frontmatter(text)
    if frontmatter is None:
        _finding(findings, "AST04", "high", error or "invalid SKILL.md frontmatter", skill_path)
        return
    _require_keys(frontmatter, {"name", "description"}, SKILL_FRONTMATTER_KEYS, skill_path, findings)
    name = frontmatter.get("name")
    if (
        not isinstance(name, str)
        or len(name) > 64
        or SKILL_NAME_RE.fullmatch(name) is None
        or name != skill_name
    ):
        _finding(findings, "AST10", "high", "SKILL.md name violates the Agent Skills specification", skill_path)
    description = frontmatter.get("description")
    if not isinstance(description, str) or not 1 <= len(description) <= 1024:
        _finding(findings, "AST10", "high", "SKILL.md description must contain 1-1024 characters", skill_path)
    compatibility = frontmatter.get("compatibility")
    if compatibility is not None and (not isinstance(compatibility, str) or len(compatibility) > 500):
        _finding(findings, "AST10", "high", "SKILL.md compatibility must contain 1-500 characters", skill_path)
    metadata = frontmatter.get("metadata")
    if metadata is not None and (
        not isinstance(metadata, dict)
        or not all(isinstance(key, str) and key and isinstance(value, str) for key, value in metadata.items())
    ):
        _finding(findings, "AST04", "high", "SKILL.md metadata must be a string-to-string map", skill_path)
    if not isinstance(metadata, dict) or metadata.get("security_manifest") != MANIFEST_NAME:
        _finding(findings, "AST10", "medium", "SKILL.md is not linked to its security manifest", skill_path)


def _validate_schema(manifest: dict[str, Any], skill_name: str, findings: list[Finding]) -> None:
    manifest_path = f"{skill_name}/{MANIFEST_NAME}"
    top_keys = {
        "schema",
        "name",
        "version",
        "description",
        "author",
        "platforms",
        "permissions",
        "requires",
        "risk_tier",
        "security",
        "provenance",
        "integrity",
    }
    _require_keys(manifest, top_keys, top_keys, manifest_path, findings)
    if manifest.get("schema") != SCHEMA_VERSION:
        _finding(findings, "AST04", "high", f"schema must be {SCHEMA_VERSION}", manifest_path)
    if manifest.get("name") != skill_name:
        _finding(findings, "AST04", "high", "manifest name does not match directory", manifest_path)
    version = manifest.get("version")
    version_path = ROOT / skill_name / "VERSION"
    package_version = version_path.read_text(encoding="utf-8").strip() if version_path.is_file() else None
    if not isinstance(version, str) or SEMVER_RE.fullmatch(version) is None:
        _finding(findings, "AST07", "medium", "version must be a semantic version", manifest_path)
    elif package_version != version:
        _finding(findings, "AST07", "medium", "manifest version must match VERSION", manifest_path)
    if not isinstance(manifest.get("description"), str) or not manifest.get("description"):
        _finding(findings, "AST04", "high", "description must be a non-empty string", manifest_path)
    if not _string_list(manifest.get("platforms")) or not manifest.get("platforms"):
        _finding(findings, "AST10", "medium", "platforms must be a non-empty string list", manifest_path)
    if manifest.get("risk_tier") not in {"L0", "L1", "L2", "L3"}:
        _finding(findings, "AST04", "high", "risk_tier must be L0, L1, L2, or L3", manifest_path)

    author = manifest.get("author")
    if not isinstance(author, dict):
        _finding(findings, "AST02", "critical", "author must be an object", manifest_path)
    else:
        author_keys = {"name", "identity"}
        _require_keys(author, author_keys, author_keys, manifest_path, findings)
        if not all(isinstance(author.get(key), str) and author.get(key) for key in author_keys):
            _finding(findings, "AST02", "critical", "author fields must be non-empty strings", manifest_path)

    permissions = manifest.get("permissions")
    if not isinstance(permissions, dict):
        _finding(findings, "AST03", "high", "permissions must be an object", manifest_path)
        return
    permission_keys = {"files", "network", "shell", "tools"}
    _require_keys(permissions, permission_keys, permission_keys, manifest_path, findings)
    files = permissions.get("files", {})
    if not isinstance(files, dict):
        _finding(findings, "AST03", "high", "permissions.files must be an object", manifest_path)
    else:
        file_keys = {"read", "write", "deny_read", "deny_write"}
        _require_keys(files, file_keys, file_keys, manifest_path, findings)
        file_lists = {}
        for key in file_keys:
            if not _string_list(files.get(key)):
                _finding(findings, "AST03", "high", f"permissions.files.{key} must be a string list", manifest_path)
                file_lists[key] = []
            else:
                file_lists[key] = files[key]
        denied_writes = set(file_lists["deny_write"])
        if not IDENTITY_FILES.issubset(denied_writes):
            _finding(findings, "AST03", "high", "all agent identity files must be deny-written", manifest_path)
        if any("**/*" in item or item == "**" for item in file_lists["read"] + file_lists["write"]):
            _finding(findings, "AST03", "high", "unbounded filesystem wildcard is forbidden", manifest_path)

    network = permissions.get("network", {})
    if isinstance(network, dict):
        _require_keys(network, {"allow", "deny"}, {"allow", "deny"}, manifest_path, findings)
    if not isinstance(network, dict) or network.get("deny") != "*" or not _string_list(network.get("allow")):
        _finding(findings, "AST03", "high", "network must default-deny all egress", manifest_path)
    shell = permissions.get("shell", {})
    if isinstance(shell, dict):
        _require_keys(shell, {"enabled", "commands"}, {"enabled", "commands"}, manifest_path, findings)
    if not isinstance(shell, dict) or shell.get("enabled") is not True:
        _finding(findings, "AST03", "high", "shell use must be explicitly declared", manifest_path)
    elif not _string_list(shell.get("commands")) or "*" in shell.get("commands", []):
        _finding(findings, "AST03", "high", "shell commands must use a non-empty allowlist", manifest_path)
    if not _string_list(permissions.get("tools")):
        _finding(findings, "AST03", "high", "permissions.tools must be a non-empty string list", manifest_path)

    requires = manifest.get("requires")
    if not isinstance(requires, dict):
        _finding(findings, "AST02", "critical", "requires must be an object", manifest_path)
    else:
        requires_keys = {"binaries", "python", "dependencies"}
        _require_keys(requires, requires_keys, requires_keys, manifest_path, findings)
        if (
            not _string_list(requires.get("binaries"))
            or not requires.get("binaries")
            or not isinstance(requires.get("python"), str)
        ):
            _finding(findings, "AST02", "high", "runtime requirements are malformed", manifest_path)
        if requires.get("dependencies") != []:
            _finding(findings, "AST02", "critical", "third-party dependencies require explicit review", manifest_path)

    security = manifest.get("security", {})
    if not isinstance(security, dict):
        _finding(findings, "AST04", "high", "security must be an object", manifest_path)
    else:
        security_keys = {
            "target_code_execution",
            "external_instructions",
            "identity_file_access",
            "dynamic_analysis",
            "data_handling",
        }
        _require_keys(security, security_keys, security_keys, manifest_path, findings)
        if security.get("target_code_execution") is not False:
            _finding(findings, "AST06", "high", "target code execution must remain disabled", manifest_path)
        if security.get("identity_file_access") != "denied":
            _finding(findings, "AST03", "high", "identity-file access must be denied", manifest_path)
        external_instructions = security.get("external_instructions")
        if not isinstance(external_instructions, list):
            _finding(findings, "AST05", "high", "external_instructions must be a list", manifest_path)
        else:
            network_allow = network.get("allow", []) if isinstance(network, dict) else []
            allowed_domains = set(network_allow) if _string_list(network_allow) else set()
            for item in external_instructions:
                if not isinstance(item, dict):
                    _finding(findings, "AST05", "high", "external instruction must be an object", manifest_path)
                    continue
                external_keys = {"url", "sha256", "purpose"}
                _require_keys(item, external_keys, external_keys, manifest_path, findings)
                url = item.get("url")
                digest = item.get("sha256")
                if not isinstance(url, str) or not url.startswith("https://"):
                    _finding(findings, "AST05", "high", "external instruction URL must use HTTPS", manifest_path)
                if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                    _finding(findings, "AST05", "high", "external instruction must be SHA-256 pinned", manifest_path)
                if isinstance(url, str):
                    domain = url.split("/", 3)[2] if url.startswith("https://") else ""
                    if domain not in allowed_domains:
                        _finding(findings, "AST03", "high", "external instruction domain is not allowlisted", manifest_path)

    provenance = manifest.get("provenance", {})
    if not isinstance(provenance, dict):
        _finding(findings, "AST02", "critical", "provenance must be an object", manifest_path)
    else:
        provenance_keys = {"repository", "publisher_identity", "signature_status", "release_tag"}
        _require_keys(provenance, provenance_keys, provenance_keys, manifest_path, findings)
        if provenance.get("signature_status") not in {"unsigned-development", "verified"}:
            _finding(findings, "AST01", "critical", "invalid signature_status", manifest_path)
        expected_release_tag = f"v{version}" if isinstance(version, str) else None
        if provenance.get("release_tag") != expected_release_tag:
            _finding(findings, "AST07", "medium", "release_tag must match the manifest version", manifest_path)

    skill_path = ROOT / skill_name / "SKILL.md"
    if skill_path.is_file():
        skill_text = skill_path.read_text(encoding="utf-8")
        _validate_skill_frontmatter(skill_name, skill_text, findings)
        frontmatter, _ = _parse_skill_frontmatter(skill_text)
        metadata = frontmatter.get("metadata") if isinstance(frontmatter, dict) else None
        if isinstance(metadata, dict) and metadata.get("version") != version:
            _finding(findings, "AST07", "medium", "SKILL.md metadata version must match manifest", manifest_path)
    else:
        _finding(findings, "AST10", "high", "skill package is missing SKILL.md", manifest_path)


def _scan_payload(skill_dir: Path, manifest: dict[str, Any], findings: list[Finding]) -> None:
    skill_name = skill_dir.name
    security = manifest.get("security")
    if not isinstance(security, dict):
        security = {}
    external_inventory = security.get("external_instructions", [])
    if not isinstance(external_inventory, list):
        external_inventory = []
    declared_urls = {item.get("url") for item in external_inventory if isinstance(item, dict)}
    permissions = manifest.get("permissions")
    if not isinstance(permissions, dict):
        permissions = {}
    network = permissions.get("network")
    if not isinstance(network, dict):
        network = {}
    network_allowed = network.get("allow", [])
    if not _string_list(network_allowed):
        network_allowed = []

    for path in _payload_files(skill_dir):
        relative = _display_path(path)
        if path.is_symlink():
            _finding(findings, "AST02", "critical", "symlink payload may escape the package root", relative)
            continue
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            _finding(findings, "AST08", "high", "binary or archive payload is not allowed", relative)
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            _finding(findings, "AST08", "medium", "unrecognized file type requires review", relative)
            continue
        if path.stat().st_size > MAX_TEXT_BYTES:
            _finding(findings, "AST08", "high", "oversized payload rejected without truncation", relative)
            continue
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            _finding(findings, "AST04", "high", "text payload is not valid UTF-8", relative)
            continue
        for match in ZERO_WIDTH_RE.finditer(text):
            _finding(findings, "AST04", "high", "zero-width Unicode detected", relative, _line_for(text, match.start()))
        for index, character in enumerate(text):
            if ord(character) < 32 and character not in "\n\r\t":
                _finding(findings, "AST04", "high", "ASCII control character detected", relative, _line_for(text, index))
        for match in UNSAFE_YAML_RE.finditer(text):
            _finding(findings, "AST04", "critical", "unsafe YAML tag detected", relative, _line_for(text, match.start()))
        for match in BASE64_RE.finditer(text):
            _finding(findings, "AST04", "high", "long base64-like payload requires review", relative, _line_for(text, match.start()))
        for match in URL_RE.finditer(text):
            url = match.group(0).rstrip(".,;:")
            if url not in declared_urls:
                _finding(findings, "AST05", "high", f"undeclared external reference: {url}", relative, _line_for(text, match.start()))
        if path.suffix == ".py":
            if NETWORK_CODE_RE.search(text) and not network_allowed:
                _finding(findings, "AST03", "high", "observed network capability is undeclared", relative)
            if PROCESS_CODE_RE.search(text):
                _finding(findings, "AST06", "high", "analyzer spawns a process", relative)
            if DYNAMIC_CODE_RE.search(text):
                _finding(findings, "AST01", "critical", "dynamic code execution detected", relative)


def validate_skill(skill_dir: Path) -> tuple[dict[str, Any] | None, list[Finding]]:
    findings: list[Finding] = []
    manifest_path = skill_dir / MANIFEST_NAME
    relative_manifest = _display_path(manifest_path)
    if manifest_path.is_symlink():
        _finding(findings, "AST02", "critical", "manifest must not be a symlink", relative_manifest)
        return None, findings
    if not manifest_path.is_file():
        _finding(findings, "AST03", "high", "missing permission/security manifest", relative_manifest)
        return None, findings
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        _finding(findings, "AST04", "critical", f"invalid manifest: {error}", relative_manifest)
        return None, findings
    if not isinstance(manifest, dict):
        _finding(findings, "AST04", "critical", "manifest root must be an object", relative_manifest)
        return None, findings

    _validate_schema(manifest, skill_dir.name, findings)
    _scan_payload(skill_dir, manifest, findings)
    actual_hashes = _payload_hashes(skill_dir)
    integrity = manifest.get("integrity", {})
    if not isinstance(integrity, dict):
        _finding(findings, "AST02", "critical", "integrity must be an object", relative_manifest)
    else:
        integrity_keys = {"algorithm", "content_hash", "files"}
        _require_keys(integrity, integrity_keys, integrity_keys, relative_manifest, findings)
        if integrity.get("algorithm") != "sha256":
            _finding(findings, "AST02", "critical", "integrity algorithm must be sha256", relative_manifest)
        if integrity.get("files") != actual_hashes:
            _finding(findings, "AST02", "critical", "file inventory or digest drift detected", relative_manifest)
        if integrity.get("content_hash") != _content_hash(actual_hashes):
            _finding(findings, "AST07", "medium", "aggregate content hash drift detected", relative_manifest)
    return manifest, findings


def prepare_manifest_refresh(skill_dir: Path) -> tuple[Path, str]:
    manifest_path = skill_dir / MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError(f"{_display_path(manifest_path)} must be a regular file")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {_display_path(manifest_path)}: {error}") from error
    if not isinstance(manifest, dict):
        raise ValueError(f"{_display_path(manifest_path)} root must be an object")
    findings: list[Finding] = []
    _validate_schema(manifest, skill_dir.name, findings)
    _scan_payload(skill_dir, manifest, findings)
    if findings:
        details = "; ".join(f"{finding.rule_id}: {finding.message}" for finding in findings)
        raise ValueError(f"refresh preflight rejected {skill_dir.name}: {details}")
    file_hashes = _payload_hashes(skill_dir)
    manifest["integrity"] = {
        "algorithm": "sha256",
        "content_hash": _content_hash(file_hashes),
        "files": file_hashes,
    }
    return manifest_path, json.dumps(manifest, indent=2, sort_keys=False) + "\n"


def _refresh_plan(skill_names: list[str]) -> dict[str, Any]:
    return {
        "schema": "vldmr.manifest-refresh.plan.v1",
        "mode": "apply",
        "resources_planned": {
            "manifests": [f"{skill_name}/{MANIFEST_NAME}" for skill_name in skill_names]
        },
        "external_commands_planned": [],
        "network_after_apply": [],
        "writes_started": False,
        "next_safe_action": "review plan, then rerun with --refresh --apply",
    }


def _sarif(findings: list[Finding], skill_names: list[str]) -> dict[str, Any]:
    rules = sorted({finding.rule_id for finding in findings})
    artifact_paths = []
    for skill_name in skill_names:
        skill_dir = ROOT / skill_name
        artifact_paths.extend([skill_dir / MANIFEST_NAME, *_payload_files(skill_dir)])
    artifacts = []
    artifact_indexes = {}
    for index, path in enumerate(sorted(artifact_paths, key=_display_path)):
        display_path = _display_path(path)
        artifact_indexes[display_path] = index
        artifacts.append(
            {
                "location": {"uri": display_path},
                "hashes": {"sha-256": _sha256_path(path)},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vldmr-skill-security",
                        "version": "1.0.0",
                        "rules": [{"id": rule} for rule in rules],
                    }
                },
                "artifacts": artifacts,
                "results": [
                    {
                        "ruleId": finding.rule_id,
                        "level": {"critical": "error", "high": "error", "medium": "warning"}.get(
                            finding.severity, "note"
                        ),
                        "message": {"text": finding.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": finding.path,
                                        **(
                                            {"index": artifact_indexes[finding.path]}
                                            if finding.path in artifact_indexes
                                            else {}
                                        ),
                                    },
                                    **(
                                        {"region": {"startLine": finding.line}}
                                        if finding.line is not None
                                        else {}
                                    ),
                                }
                            }
                        ],
                        "properties": {"layer": "content", "severity": finding.severity},
                    }
                    for finding in findings
                ],
            }
        ],
    }


def _skill_name(value: str) -> str:
    if value not in SKILL_NAMES:
        choices = ", ".join(SKILL_NAMES)
        raise argparse.ArgumentTypeError(f"invalid skill: {value!r} (choose from {choices})")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("skills", nargs="*", type=_skill_name, help="skills to validate")
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root to validate")
    parser.add_argument("--refresh", action="store_true", help="plan a payload-hash refresh")
    parser.add_argument("--apply", action="store_true", help="apply a planned payload-hash refresh")
    parser.add_argument("--format", choices=("json", "sarif"), default="json")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    global ROOT

    args = parse_args()
    ROOT = args.root.resolve()
    skill_names = args.skills or list(SKILL_NAMES)
    if args.apply and not args.refresh:
        print("error: --apply requires --refresh", file=sys.stderr)
        return 2
    if args.refresh:
        plan = _refresh_plan(skill_names)
        receipt = json.dumps(plan, indent=2, sort_keys=True) + "\n"
        if not args.apply:
            sys.stdout.write(receipt)
            return 0
        sys.stderr.write(receipt)
        try:
            refreshes = [prepare_manifest_refresh(ROOT / skill_name) for skill_name in skill_names]
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        for manifest_path, content in refreshes:
            manifest_path.write_text(content, encoding="utf-8")

    findings: list[Finding] = []
    packages = []
    for skill_name in skill_names:
        manifest, skill_findings = validate_skill(ROOT / skill_name)
        findings.extend(skill_findings)
        packages.append(
            {
                "name": skill_name,
                "version": manifest.get("version") if manifest else None,
                "content_hash": manifest.get("integrity", {}).get("content_hash") if manifest else None,
                "status": "pass" if not skill_findings else "fail",
                "findings": len(skill_findings),
            }
        )

    findings.sort(key=lambda item: (item.path, item.line or 0, item.rule_id, item.message))
    if args.format == "sarif":
        report = _sarif(findings, skill_names)
    else:
        report = {
            "schema": "vldmr.skill-security-report.v1",
            "tool": {"name": "vldmr-skill-security", "version": "1.0.0"},
            "packages": packages,
            "summary": {
                "skills": len(packages),
                "passed": sum(package["status"] == "pass" for package in packages),
                "failed": sum(package["status"] == "fail" for package in packages),
                "findings": len(findings),
            },
            "findings": [finding.as_dict() for finding in findings],
        }
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())