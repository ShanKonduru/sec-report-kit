from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def _severity(extra: dict) -> str:
    value = extra.get("severity")
    if not value and isinstance(extra.get("metadata"), dict):
        value = extra["metadata"].get("severity")
    return normalize_severity(value)


def _primary_url(extra: dict) -> str:
    metadata = extra.get("metadata")
    if isinstance(metadata, dict):
        refs = metadata.get("references")
        if isinstance(refs, list) and refs:
            return str(refs[0])
    return ""


def parse_semgrep_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []

    for issue in data.get("results", []) if isinstance(data, dict) else []:
        extra = issue.get("extra") if isinstance(issue.get("extra"), dict) else {}
        findings.append(
            Finding(
                source_type="semgrep-sast",
                target=str(issue.get("path") or "repository"),
                severity=_severity(extra),
                vulnerability_id=str(issue.get("check_id") or "-"),
                package=str(issue.get("check_id") or "semgrep-rule"),
                installed_version="-",
                fixed_version="-",
                title=str(extra.get("message") or issue.get("check_id") or "Semgrep finding"),
                primary_url=_primary_url(extra),
            )
        )

    return findings
