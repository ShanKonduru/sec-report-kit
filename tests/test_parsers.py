from sec_report_kit.parsers.pip_audit import parse_pip_audit_json
from sec_report_kit.parsers.trivy import parse_trivy_json
from sec_report_kit.services.summarize import count_by_severity


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
