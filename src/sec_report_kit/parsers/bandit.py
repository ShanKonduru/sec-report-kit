from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def _best_url(issue: dict) -> str:
    cwe = issue.get("issue_cwe")
    if isinstance(cwe, dict) and cwe.get("link"):
        return str(cwe["link"])
    if issue.get("more_info"):
        return str(issue["more_info"])
    return ""


def parse_bandit_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []

    results = data.get("results", []) if isinstance(data, dict) else []
    for issue in results:
        findings.append(
            Finding(
                source_type="python-sast",
                target=str(issue.get("filename") or "Python"),
                severity=normalize_severity(issue.get("issue_severity")),
                vulnerability_id=str(issue.get("test_id") or "-"),
                package=str(issue.get("test_name") or "-"),
                installed_version="-",
                fixed_version="-",
                title=str(issue.get("issue_text") or "-"),
                primary_url=_best_url(issue),
            )
        )

    return findings
