from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def _extract_findings(data: dict | list) -> list[dict]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict) and (
        "DetectorName" in data
        or "DetectorType" in data
        or "SourceName" in data
    ):
        return [data]
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return [item for item in data["results"] if isinstance(item, dict)]
    return []


def _target(entry: dict) -> str:
    source_meta = entry.get("SourceMetadata")
    if isinstance(source_meta, dict):
        data = source_meta.get("Data")
        if isinstance(data, dict):
            fs = data.get("Filesystem")
            if isinstance(fs, dict) and fs.get("file"):
                return str(fs["file"])
            git = data.get("Git")
            if isinstance(git, dict) and git.get("file"):
                return str(git["file"])
    return str(entry.get("SourceName") or "repository")


def parse_trufflehog_json(data: dict | list) -> list[Finding]:
    findings: list[Finding] = []

    for entry in _extract_findings(data):
        detector = str(entry.get("DetectorName") or entry.get("DetectorType") or "trufflehog-detector")
        verified = bool(entry.get("Verified"))
        severity = "HIGH" if verified else "MEDIUM"

        findings.append(
            Finding(
                source_type="secret-scan",
                target=_target(entry),
                severity=normalize_severity(severity),
                vulnerability_id=detector,
                package=detector,
                installed_version="-",
                fixed_version="-",
                title=f"Potential secret detected by {detector}",
                primary_url="",
            )
        )

    return findings
