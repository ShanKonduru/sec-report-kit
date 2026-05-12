from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def parse_tfsec_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []

    for issue in data.get("results", []) if isinstance(data, dict) else []:
        location = issue.get("location") if isinstance(issue.get("location"), dict) else {}
        filename = str(location.get("filename") or issue.get("location") or "infrastructure-code")
        start_line = location.get("start_line")
        title = str(issue.get("description") or issue.get("rule_description") or "tfsec finding")
        if isinstance(start_line, int):
            title = f"{title} ({filename}:{start_line})"

        links = issue.get("links") if isinstance(issue.get("links"), list) else []
        primary_url = str(links[0]) if links else ""

        findings.append(
            Finding(
                source_type="tfsec-iac",
                target=filename,
                severity=normalize_severity(issue.get("severity")),
                vulnerability_id=str(issue.get("rule_id") or "-"),
                package=str(issue.get("rule_id") or "tfsec-rule"),
                installed_version="-",
                fixed_version="-",
                title=title,
                primary_url=primary_url,
            )
        )

    return findings
