from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def _severity(vuln: dict) -> str:
    sev = vuln.get("severity")
    if isinstance(sev, dict):
        for key in ("level", "name", "value"):
            if sev.get(key):
                return normalize_severity(str(sev.get(key)))
        return "UNKNOWN"
    return normalize_severity(str(sev)) if sev else "UNKNOWN"


def _fixed_version(vuln: dict) -> str:
    fixed = vuln.get("fixed_versions") or vuln.get("fix_versions")
    if isinstance(fixed, list) and fixed:
        return ", ".join(str(value) for value in fixed)
    if vuln.get("fixed_version"):
        return str(vuln.get("fixed_version"))
    return "-"


def _vuln_id(vuln: dict) -> str:
    return str(vuln.get("vulnerability_id") or vuln.get("id") or vuln.get("CVE") or "-")


def _title(vuln: dict) -> str:
    return str(vuln.get("advisory") or vuln.get("description") or vuln.get("summary") or "Safety finding")


def _primary_url(vuln: dict) -> str:
    if vuln.get("more_info_url"):
        return str(vuln["more_info_url"])
    if vuln.get("url"):
        return str(vuln["url"])
    if isinstance(vuln.get("references"), list) and vuln["references"]:
        first = vuln["references"][0]
        if isinstance(first, dict):
            return str(first.get("url") or "")
        return str(first)
    return ""


def parse_safety_json(data: dict | list) -> list[Finding]:
    findings: list[Finding] = []

    vulnerabilities: list[dict] = []
    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        vulnerabilities = [item for item in data["vulnerabilities"] if isinstance(item, dict)]
    elif isinstance(data, list):
        vulnerabilities = [item for item in data if isinstance(item, dict)]

    for vuln in vulnerabilities:
        findings.append(
            Finding(
                source_type="safety",
                target="Python",
                severity=_severity(vuln),
                vulnerability_id=_vuln_id(vuln),
                package=str(vuln.get("package_name") or vuln.get("package") or "-"),
                installed_version=str(vuln.get("analyzed_version") or vuln.get("installed_version") or "-"),
                fixed_version=_fixed_version(vuln),
                title=_title(vuln),
                primary_url=_primary_url(vuln),
            )
        )

    return findings