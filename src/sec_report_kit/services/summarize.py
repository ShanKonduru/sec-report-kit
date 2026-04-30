from __future__ import annotations

from collections.abc import Iterable

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import SEVERITY_ORDER


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            item.package.lower(),
            item.vulnerability_id.lower(),
        ),
    )


def count_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return counts
