from sec_report_kit.parsers import detect_source_type
from sec_report_kit.parsers.bandit import parse_bandit_json
from sec_report_kit.parsers.gitleaks import parse_gitleaks_json
from sec_report_kit.parsers.pip_audit import parse_pip_audit_json
from sec_report_kit.parsers.trivy import parse_trivy_json
from sec_report_kit.services.summarize import count_by_severity, sort_findings
import pytest


def test_parse_trivy_json_basic():
    payload = {
        "Results": [
            {
                "Target": "myimage:1",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "Severity": "HIGH",
                        "VulnerabilityID": "CVE-1",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Title": "Example",
                        "PrimaryURL": "https://example.com",
                    }
                ],
            }
        ]
    }

    findings = parse_trivy_json(payload)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].package == "openssl"


def test_parse_pip_audit_json_basic():
    payload = {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.31.0",
                "vulns": [
                    {
                        "id": "GHSA-xxxx",
                        "fix_versions": ["2.32.0"],
                        "description": "Example vuln",
                        "url": "https://example.com/advisory",
                    }
                ],
            }
        ]
    }

    findings = parse_pip_audit_json(payload)
    assert len(findings) == 1
    assert findings[0].package == "requests"
    assert findings[0].fixed_version == "2.32.0"


def test_count_by_severity_unknown_when_missing():
    payload = {
        "dependencies": [
            {
                "name": "pkg",
                "version": "1.0.0",
                "vulns": [{"id": "PYSEC-1", "description": "no severity"}],
            }
        ]
    }

    findings = parse_pip_audit_json(payload)
    counts = count_by_severity(findings)
    assert counts["UNKNOWN"] == 1


# ---------- detect_source_type ----------

def test_detect_source_type_trivy():
    assert detect_source_type({"Results": []}) == "trivy"


def test_detect_source_type_pip_audit_dependencies():
    assert detect_source_type({"dependencies": []}) == "pip-audit"


def test_detect_source_type_pip_audit_vulnerabilities():
    assert detect_source_type({"vulnerabilities": []}) == "pip-audit"


def test_detect_source_type_invalid_raises():
    with pytest.raises(ValueError):
        detect_source_type({"unknown_key": 1})


# ---------- pip_audit URL / fixed_version branches ----------

def test_pip_audit_best_url_from_url():
    payload = {
        "dependencies": [
            {
                "name": "pkg",
                "version": "1.0",
                "vulns": [{"id": "ID-1", "url": "https://example.com/url"}],
            }
        ]
    }
    findings = parse_pip_audit_json(payload)
    assert findings[0].primary_url == "https://example.com/url"


def test_pip_audit_best_url_from_advisory():
    payload = {
        "dependencies": [
            {
                "name": "pkg",
                "version": "1.0",
                "vulns": [{"id": "ID-2", "advisory": "https://example.com/advisory"}],
            }
        ]
    }
    findings = parse_pip_audit_json(payload)
    assert findings[0].primary_url == "https://example.com/advisory"


def test_pip_audit_best_url_from_links():
    payload = {
        "dependencies": [
            {
                "name": "pkg",
                "version": "1.0",
                "vulns": [{"id": "ID-3", "links": ["https://example.com/link"]}],
            }
        ]
    }
    findings = parse_pip_audit_json(payload)
    assert findings[0].primary_url == "https://example.com/link"


def test_pip_audit_best_url_empty():
    payload = {
        "dependencies": [
            {"name": "pkg", "version": "1.0", "vulns": [{"id": "ID-4"}]}
        ]
    }
    findings = parse_pip_audit_json(payload)
    assert findings[0].primary_url == ""


def test_pip_audit_fixed_version_string():
    payload = {
        "dependencies": [
            {
                "name": "pkg",
                "version": "1.0",
                "vulns": [{"id": "ID-5", "fixed_version": "2.0"}],
            }
        ]
    }
    findings = parse_pip_audit_json(payload)
    assert findings[0].fixed_version == "2.0"


def test_pip_audit_flat_vulnerabilities_format():
    payload = {
        "vulnerabilities": [
            {
                "id": "FLAT-1",
                "package": "flatpkg",
                "installed_version": "0.1",
                "fix_versions": ["0.2"],
                "description": "Flat vuln",
                "url": "https://example.com",
                "severity": "HIGH",
            }
        ]
    }
    findings = parse_pip_audit_json(payload)
    assert len(findings) == 1
    assert findings[0].package == "flatpkg"
    assert findings[0].severity == "HIGH"


# ---------- sort_findings ----------

def test_sort_findings_orders_by_severity_then_package():
    payload = {
        "dependencies": [
            {
                "name": "b-pkg",
                "version": "1.0",
                "vulns": [{"id": "ID-HIGH", "severity": "HIGH"}],
            },
            {
                "name": "a-pkg",
                "version": "1.0",
                "vulns": [{"id": "ID-CRIT", "severity": "CRITICAL"}],
            },
        ]
    }
    findings = parse_pip_audit_json(payload)
    sorted_findings = sort_findings(findings)
    assert sorted_findings[0].severity == "CRITICAL"
    assert sorted_findings[1].severity == "HIGH"


def test_parse_bandit_json_basic():
    payload = {
        "results": [
            {
                "filename": "src/app.py",
                "issue_severity": "HIGH",
                "issue_text": "Use of assert detected.",
                "test_id": "B101",
                "test_name": "assert_used",
                "issue_cwe": {"id": 703, "link": "https://cwe.mitre.org/data/definitions/703.html"},
            }
        ]
    }

    findings = parse_bandit_json(payload)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].vulnerability_id == "B101"
    assert findings[0].target == "src/app.py"


def test_detect_source_type_bandit():
    payload = {
        "results": [
            {
                "filename": "src/app.py",
                "issue_severity": "LOW",
            }
        ]
    }

    assert detect_source_type(payload) == "bandit"


def test_parse_gitleaks_json_basic():
    payload = [
        {
            "RuleID": "generic-api-key",
            "Description": "Hardcoded API key",
            "File": "src/settings.py",
            "StartLine": 42,
            "Fingerprint": "src/settings.py:generic-api-key:42",
        }
    ]

    findings = parse_gitleaks_json(payload)
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "generic-api-key"
    assert findings[0].target == "src/settings.py"
    assert findings[0].severity == "UNKNOWN"


def test_detect_source_type_gitleaks():
    payload = [
        {
            "RuleID": "generic-api-key",
            "Description": "Hardcoded API key",
            "File": "src/settings.py",
        }
    ]

    assert detect_source_type(payload) == "gitleaks"
