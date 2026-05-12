from __future__ import annotations

from sec_report_kit.models import Finding
from sec_report_kit.services.normalize import normalize_severity


def _extract_rule_index(result: dict) -> int | None:
    locations = result.get("locations")
    if isinstance(locations, list) and locations:
        logical = locations[0].get("logicalLocations")
        if isinstance(logical, list) and logical:
            idx = logical[0].get("index")
            if isinstance(idx, int):
                return idx
    return None


def _rule_info(run: dict, result: dict) -> tuple[str, str, str]:
    # Returns rule id, title, primary_url.
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    rule_id = str(result.get("ruleId") or "-")
    title = str(result.get("message", {}).get("text") or "CodeQL finding")
    primary_url = ""

    for rule in rules if isinstance(rules, list) else []:
        if str(rule.get("id") or "") == rule_id:
            title = str(rule.get("shortDescription", {}).get("text") or title)
            primary_url = str(rule.get("helpUri") or "")
            return rule_id, title, primary_url

    idx = _extract_rule_index(result)
    if idx is not None and 0 <= idx < len(rules):
        rule = rules[idx]
        rule_id = str(rule.get("id") or rule_id)
        title = str(rule.get("shortDescription", {}).get("text") or title)
        primary_url = str(rule.get("helpUri") or "")

    return rule_id, title, primary_url


def parse_codeql_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []

    for run in data.get("runs", []) if isinstance(data, dict) else []:
        for result in run.get("results", []) if isinstance(run, dict) else []:
            level = result.get("level")
            if isinstance(level, str):
                sev_map = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}
                severity = sev_map.get(level.lower(), "UNKNOWN")
            else:
                severity = "UNKNOWN"

            rule_id, title, primary_url = _rule_info(run, result)

            target = "repository"
            locations = result.get("locations")
            if isinstance(locations, list) and locations:
                phys = locations[0].get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {}) if isinstance(phys, dict) else {}
                target = str(artifact.get("uri") or target)

            findings.append(
                Finding(
                    source_type="codeql-sast",
                    target=target,
                    severity=normalize_severity(severity),
                    vulnerability_id=rule_id,
                    package=rule_id,
                    installed_version="-",
                    fixed_version="-",
                    title=title,
                    primary_url=primary_url,
                )
            )

    return findings
