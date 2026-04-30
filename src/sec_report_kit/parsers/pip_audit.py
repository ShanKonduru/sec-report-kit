from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def _best_url(vuln: dict) -> str:
    if vuln.get("url"):
        return str(vuln["url"])
    if vuln.get("advisory"):
        return str(vuln["advisory"])
    if vuln.get("links") and isinstance(vuln["links"], list):
        return str(vuln["links"][0]) if vuln["links"] else ""
    return ""


def _fixed_version(vuln: dict) -> str:
    fixes = vuln.get("fix_versions")
    if isinstance(fixes, list) and fixes:
        return ", ".join(str(value) for value in fixes)
    fixed = vuln.get("fixed_version")
    return str(fixed) if fixed else "-"


def parse_pip_audit_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []

    dependencies = data.get("dependencies", []) if isinstance(data, dict) else []
    for dep in dependencies:
        package = dep.get("name", "-")
        installed = dep.get("version", "-")
        for vuln in dep.get("vulns", []) or []:
            findings.append(
                Finding(
                    source_type="python-pkg",
                    target="Python",
                    severity=normalize_severity(vuln.get("severity")),
                    vulnerability_id=str(vuln.get("id") or "-"),
                    package=str(package),
                    installed_version=str(installed),
                    fixed_version=_fixed_version(vuln),
                    title=str(vuln.get("description") or vuln.get("summary") or "-"),
                    primary_url=_best_url(vuln),
                )
            )

    # Some tools may output a flat list under "vulnerabilities"; support that too.
    if not findings and isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        for vuln in data["vulnerabilities"]:
            findings.append(
                Finding(
                    source_type="python-pkg",
                    target="Python",
                    severity=normalize_severity(vuln.get("severity")),
                    vulnerability_id=str(vuln.get("id") or "-"),
                    package=str(vuln.get("package") or "-"),
                    installed_version=str(vuln.get("installed_version") or "-"),
                    fixed_version=_fixed_version(vuln),
                    title=str(vuln.get("description") or vuln.get("summary") or "-"),
                    primary_url=_best_url(vuln),
                )
            )

    return findings
