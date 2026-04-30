from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def parse_trivy_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results", []):
        target = result.get("Target", "unknown")
        source_type = result.get("Type", "unknown")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                Finding(
                    source_type=source_type,
                    target=target,
                    severity=normalize_severity(vuln.get("Severity")),
                    vulnerability_id=vuln.get("VulnerabilityID", "-"),
                    package=vuln.get("PkgName", "-"),
                    installed_version=vuln.get("InstalledVersion", "-"),
                    fixed_version=vuln.get("FixedVersion") or "-",
                    title=vuln.get("Title") or "-",
                    primary_url=vuln.get("PrimaryURL") or "",
                )
            )
    return findings
