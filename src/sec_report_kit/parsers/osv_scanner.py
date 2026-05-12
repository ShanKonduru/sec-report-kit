from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def _severity(vuln: dict) -> str:
    db_specific = vuln.get("database_specific")
    if isinstance(db_specific, dict) and db_specific.get("severity"):
        return normalize_severity(str(db_specific["severity"]))
    if isinstance(vuln.get("severity"), list) and vuln["severity"]:
        value = vuln["severity"][0]
        if isinstance(value, dict) and value.get("type") == "CVSS_V3":
            score = value.get("score")
            try:
                score = float(score)
            except (TypeError, ValueError):
                return "UNKNOWN"
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"
    return "UNKNOWN"


def parse_osv_scanner_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []

    for result in data.get("results", []) if isinstance(data, dict) else []:
        for package_block in result.get("packages", []) if isinstance(result, dict) else []:
            package = package_block.get("package", {}) if isinstance(package_block, dict) else {}
            pkg_name = str(package.get("name") or "-")
            pkg_version = str(package.get("version") or "-")

            for vuln in package_block.get("vulnerabilities", []) if isinstance(package_block, dict) else []:
                aliases = vuln.get("aliases") if isinstance(vuln.get("aliases"), list) else []
                vuln_id = str(vuln.get("id") or (aliases[0] if aliases else "-"))
                refs = vuln.get("references") if isinstance(vuln.get("references"), list) else []
                primary_url = ""
                if refs and isinstance(refs[0], dict):
                    primary_url = str(refs[0].get("url") or "")

                findings.append(
                    Finding(
                        source_type="osv-scanner",
                        target=str(result.get("source", {}).get("path") or "dependency-manifest"),
                        severity=_severity(vuln),
                        vulnerability_id=vuln_id,
                        package=pkg_name,
                        installed_version=pkg_version,
                        fixed_version="-",
                        title=str(vuln.get("summary") or vuln.get("details") or "OSV vulnerability"),
                        primary_url=primary_url,
                    )
                )

    return findings
