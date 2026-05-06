from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def _extract_findings(data: dict | list) -> list[dict]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [item for item in data["findings"] if isinstance(item, dict)]
    return []


def _build_title(entry: dict) -> str:
    description = str(entry.get("Description") or "Potential secret detected")
    file_path = str(entry.get("File") or "unknown-file")
    start_line = entry.get("StartLine")
    if start_line is not None:
        return f"{description} ({file_path}:{start_line})"
    return f"{description} ({file_path})"


def parse_gitleaks_json(data: dict | list) -> list[Finding]:
    findings: list[Finding] = []

    for entry in _extract_findings(data):
        findings.append(
            Finding(
                source_type="secret-scan",
                target=str(entry.get("File") or "repository"),
                severity=normalize_severity(entry.get("Severity")),
                vulnerability_id=str(entry.get("RuleID") or entry.get("Fingerprint") or "-"),
                package=str(entry.get("RuleID") or "gitleaks-rule"),
                installed_version="-",
                fixed_version="-",
                title=_build_title(entry),
                primary_url="",
            )
        )

    return findings
