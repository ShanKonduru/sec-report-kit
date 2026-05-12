from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def parse_checkov_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []

    results = data.get("results", {}) if isinstance(data, dict) else {}
    failed = results.get("failed_checks", []) if isinstance(results, dict) else []

    for issue in failed:
        guideline = issue.get("guideline")
        findings.append(
            Finding(
                source_type="checkov-iac",
                target=str(issue.get("file_path") or issue.get("resource") or "infrastructure-code"),
                severity=normalize_severity(issue.get("severity")),
                vulnerability_id=str(issue.get("check_id") or "-"),
                package=str(issue.get("check_name") or "checkov-rule"),
                installed_version="-",
                fixed_version="-",
                title=str(issue.get("check_name") or issue.get("guideline") or "Checkov finding"),
                primary_url=str(guideline) if guideline else "",
            )
        )

    return findings
