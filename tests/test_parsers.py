from sec_report_kit.parsers import detect_source_type
from sec_report_kit.parsers.bandit import parse_bandit_json
from sec_report_kit.parsers.checkov import parse_checkov_json
from sec_report_kit.parsers.codeql import parse_codeql_json
from sec_report_kit.parsers.gitleaks import parse_gitleaks_json
from sec_report_kit.parsers.osv_scanner import parse_osv_scanner_json
from sec_report_kit.parsers.pip_audit import parse_pip_audit_json
from sec_report_kit.parsers.safety import parse_safety_json
from sec_report_kit.parsers.semgrep import parse_semgrep_json
from sec_report_kit.parsers.tfsec import parse_tfsec_json
from sec_report_kit.parsers.trivy import parse_trivy_json
from sec_report_kit.parsers.trufflehog import parse_trufflehog_json
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


def test_parse_safety_json_basic():
    payload = {
        "report_meta": {"scan_target": "environment"},
        "vulnerabilities": [
            {
                "vulnerability_id": "12345",
                "package_name": "urllib3",
                "analyzed_version": "1.26.0",
                "fixed_versions": ["1.26.19"],
                "severity": "high",
                "advisory": "Example advisory",
                "more_info_url": "https://example.com/safety/12345",
            }
        ],
    }

    findings = parse_safety_json(payload)
    assert len(findings) == 1
    assert findings[0].package == "urllib3"
    assert findings[0].severity == "HIGH"
    assert findings[0].fixed_version == "1.26.19"


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


def test_detect_source_type_safety_vulnerabilities():
    payload = {
        "report_meta": {"generated": "2026-05-13"},
        "vulnerabilities": [
            {
                "vulnerability_id": "123",
                "package_name": "jinja2",
                "analyzed_version": "3.0.0",
            }
        ],
    }

    assert detect_source_type(payload) == "safety"


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


def test_detect_source_type_gitleaks_findings_dict():
    payload = {
        "findings": [
            {
                "RuleID": "generic-api-key",
                "File": "src/settings.py",
            }
        ]
    }

    assert detect_source_type(payload) == "gitleaks"


def test_parse_bandit_json_uses_more_info_when_cwe_link_missing():
    payload = {
        "results": [
            {
                "filename": "src/app.py",
                "issue_severity": "LOW",
                "issue_text": "Issue",
                "test_id": "B102",
                "test_name": "exec_used",
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b102_exec_used.html",
            }
        ]
    }

    findings = parse_bandit_json(payload)
    assert findings[0].primary_url == "https://bandit.readthedocs.io/en/latest/plugins/b102_exec_used.html"


def test_parse_bandit_json_without_reference_url():
    payload = {
        "results": [
            {
                "filename": "src/app.py",
                "issue_severity": "LOW",
                "issue_text": "Issue",
                "test_id": "B103",
                "test_name": "set_bad_file_permissions",
            }
        ]
    }

    findings = parse_bandit_json(payload)
    assert findings[0].primary_url == ""


def test_parse_gitleaks_json_accepts_findings_dict_and_title_without_line():
    payload = {
        "findings": [
            {
                "RuleID": "generic-api-key",
                "Description": "Hardcoded API key",
                "File": "src/settings.py",
            }
        ]
    }

    findings = parse_gitleaks_json(payload)
    assert len(findings) == 1
    assert findings[0].title == "Hardcoded API key (src/settings.py)"


def test_parse_gitleaks_json_returns_empty_for_unsupported_payload_shape():
    assert parse_gitleaks_json({"unexpected": []}) == []


def test_detect_source_type_semgrep():
    payload = {
        "version": "1.0",
        "results": [{"check_id": "python.lang.security", "path": "app.py", "extra": {"severity": "HIGH"}}],
    }
    assert detect_source_type(payload) == "semgrep"


def test_parse_semgrep_json_basic():
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit",
                "path": "app.py",
                "extra": {"severity": "HIGH", "message": "Avoid weak hash"},
            }
        ]
    }
    findings = parse_semgrep_json(payload)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_detect_source_type_codeql():
    payload = {"runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}]}
    assert detect_source_type(payload) == "codeql"


def test_parse_codeql_json_basic():
    payload = {
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "py/sql-injection", "shortDescription": {"text": "SQL injection"}}]}},
                "results": [{"ruleId": "py/sql-injection", "level": "error", "message": {"text": "msg"}}],
            }
        ]
    }
    findings = parse_codeql_json(payload)
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "py/sql-injection"
    assert findings[0].severity == "HIGH"


def test_detect_source_type_osv_scanner():
    payload = {"results": [{"packages": []}]}
    assert detect_source_type(payload) == "osv-scanner"


def test_parse_osv_scanner_json_basic():
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "requests", "version": "2.0.0"},
                        "vulnerabilities": [{"id": "GHSA-1", "summary": "Issue"}],
                    }
                ],
            }
        ]
    }
    findings = parse_osv_scanner_json(payload)
    assert len(findings) == 1
    assert findings[0].package == "requests"


def test_detect_source_type_checkov():
    payload = {"results": {"failed_checks": []}}
    assert detect_source_type(payload) == "checkov"


def test_parse_checkov_json_basic():
    payload = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_1",
                    "check_name": "Ensure no public bucket",
                    "severity": "HIGH",
                    "file_path": "main.tf",
                }
            ]
        }
    }
    findings = parse_checkov_json(payload)
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "CKV_AWS_1"


def test_detect_source_type_tfsec():
    payload = {"results": [{"rule_id": "AWS001", "severity": "HIGH"}]}
    assert detect_source_type(payload) == "tfsec"


def test_parse_tfsec_json_basic():
    payload = {"results": [{"rule_id": "AWS001", "description": "Issue", "severity": "HIGH"}]}
    findings = parse_tfsec_json(payload)
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "AWS001"


def test_detect_source_type_trufflehog_array():
    payload = [{"DetectorName": "AWS"}]
    assert detect_source_type(payload) == "trufflehog"


def test_parse_trufflehog_json_basic():
    payload = [{"DetectorName": "AWS", "SourceName": "repo", "Verified": True}]
    findings = parse_trufflehog_json(payload)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


# ---------- trufflehog _extract_findings / _target branches ----------

def test_trufflehog_dict_with_results_list():
    """_extract_findings: dict with a top-level 'results' list (lines 16-17)."""
    payload = {"results": [{"DetectorName": "GitHub", "Verified": False}]}
    findings = parse_trufflehog_json(payload)
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "GitHub"
    assert findings[0].severity == "MEDIUM"


def test_trufflehog_extract_findings_returns_empty_for_non_matching_dict():
    """_extract_findings: dict with no matching keys → empty list (line 18)."""
    payload = {"other_key": "value"}
    findings = parse_trufflehog_json(payload)
    assert findings == []


def test_trufflehog_target_filesystem_path():
    """_target: SourceMetadata.Data.Filesystem.file branch (lines 24-28)."""
    payload = [
        {
            "DetectorName": "AWS",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "config/secrets.env"}}},
        }
    ]
    findings = parse_trufflehog_json(payload)
    assert findings[0].target == "config/secrets.env"


def test_trufflehog_target_git_path():
    """_target: SourceMetadata.Data.Git.file branch (lines 29-31)."""
    payload = [
        {
            "DetectorName": "AWS",
            "Verified": True,
            "SourceMetadata": {"Data": {"Git": {"file": "src/config.py"}}},
        }
    ]
    findings = parse_trufflehog_json(payload)
    assert findings[0].target == "src/config.py"


def test_trufflehog_target_falls_back_to_source_name():
    """_target: no SourceMetadata → fallback to SourceName."""
    payload = [{"DetectorName": "AWS", "Verified": False, "SourceName": "my-repo"}]
    findings = parse_trufflehog_json(payload)
    assert findings[0].target == "my-repo"


# ---------- detect_source_type: trufflehog in results list (parsers/__init__ line 50) ----------

def test_detect_source_type_trufflehog_in_results_list():
    """detect_source_type: dict with results list containing DetectorName items."""
    payload = {"results": [{"DetectorName": "GitHub", "Verified": True}]}
    assert detect_source_type(payload) == "trufflehog"


# ---------- codeql branches ----------

def test_codeql_rule_index_fallback():
    """_extract_rule_index + index fallback in _rule_info (lines 8-15, 31-38)."""
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "py/path-injection",
                                "shortDescription": {"text": "Path injection"},
                                "helpUri": "https://codeql.github.com/path",
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "no-match-rule",
                        "level": "warning",
                        "message": {"text": "Some issue"},
                        "locations": [
                            {
                                "logicalLocations": [{"index": 0}]
                            }
                        ],
                    }
                ],
            }
        ]
    }
    findings = parse_codeql_json(payload)
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "py/path-injection"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].primary_url == "https://codeql.github.com/path"


def test_codeql_severity_unknown_when_level_missing():
    """severity = 'UNKNOWN' when level is not a string (line 51)."""
    payload = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [{"ruleId": "some-rule", "message": {"text": "Issue"}}],
            }
        ]
    }
    findings = parse_codeql_json(payload)
    assert findings[0].severity == "UNKNOWN"


def test_codeql_physical_location_target():
    """Physical location uri is used as target (lines 58-60)."""
    payload = {
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "py/sql-injection", "shortDescription": {"text": "SQL"}}]}},
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "SQL injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/db/queries.py"}
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    findings = parse_codeql_json(payload)
    assert findings[0].target == "src/db/queries.py"


def test_codeql_rule_index_none_when_no_logical_locations():
    """_extract_rule_index returns None when locations list is present but has no logicalLocations."""
    payload = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {
                        "ruleId": "some-rule",
                        "level": "note",
                        "message": {"text": "Note"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}],
                    }
                ],
            }
        ]
    }
    findings = parse_codeql_json(payload)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"


# ---------- osv-scanner severity branches ----------

def test_osv_scanner_severity_database_specific():
    """_severity: database_specific.severity branch (line 10)."""
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "pkg", "version": "1.0"},
                        "vulnerabilities": [
                            {"id": "OSV-1", "database_specific": {"severity": "CRITICAL"}}
                        ],
                    }
                ],
            }
        ]
    }
    findings = parse_osv_scanner_json(payload)
    assert findings[0].severity == "CRITICAL"


def test_osv_scanner_severity_cvss_critical():
    """_severity: CVSS_V3 score >= 9.0 → CRITICAL (lines 12-20)."""
    vuln = {"severity": [{"type": "CVSS_V3", "score": "9.5"}]}
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [{"package": {"name": "pkg", "version": "1.0"}, "vulnerabilities": [{"id": "X", **vuln}]}],
            }
        ]
    }
    findings = parse_osv_scanner_json(payload)
    assert findings[0].severity == "CRITICAL"


def test_osv_scanner_severity_cvss_high():
    """_severity: CVSS_V3 score >= 7.0 → HIGH."""
    vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [{"package": {"name": "pkg", "version": "1.0"}, "vulnerabilities": [{"id": "X", **vuln}]}],
            }
        ]
    }
    findings = parse_osv_scanner_json(payload)
    assert findings[0].severity == "HIGH"


def test_osv_scanner_severity_cvss_medium():
    """_severity: CVSS_V3 score >= 4.0 → MEDIUM."""
    vuln = {"severity": [{"type": "CVSS_V3", "score": "5.0"}]}
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [{"package": {"name": "pkg", "version": "1.0"}, "vulnerabilities": [{"id": "X", **vuln}]}],
            }
        ]
    }
    findings = parse_osv_scanner_json(payload)
    assert findings[0].severity == "MEDIUM"


def test_osv_scanner_severity_cvss_low():
    """_severity: CVSS_V3 score < 4.0 → LOW."""
    vuln = {"severity": [{"type": "CVSS_V3", "score": "2.0"}]}
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [{"package": {"name": "pkg", "version": "1.0"}, "vulnerabilities": [{"id": "X", **vuln}]}],
            }
        ]
    }
    findings = parse_osv_scanner_json(payload)
    assert findings[0].severity == "LOW"


def test_osv_scanner_severity_cvss_invalid_score():
    """_severity: CVSS_V3 score cannot be converted to float → UNKNOWN."""
    vuln = {"severity": [{"type": "CVSS_V3", "score": "not-a-number"}]}
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [{"package": {"name": "pkg", "version": "1.0"}, "vulnerabilities": [{"id": "X", **vuln}]}],
            }
        ]
    }
    findings = parse_osv_scanner_json(payload)
    assert findings[0].severity == "UNKNOWN"


def test_osv_scanner_vuln_id_falls_back_to_alias():
    """vuln_id uses aliases[0] when id is missing."""
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "pkg", "version": "1.0"},
                        "vulnerabilities": [{"aliases": ["CVE-2024-9999"]}],
                    }
                ],
            }
        ]
    }
    findings = parse_osv_scanner_json(payload)
    assert findings[0].vulnerability_id == "CVE-2024-9999"


def test_osv_scanner_primary_url_from_references():
    """primary_url extracted from references[0].url."""
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "pkg", "version": "1.0"},
                        "vulnerabilities": [
                            {
                                "id": "OSV-2",
                                "references": [{"url": "https://example.com/advisory"}],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    findings = parse_osv_scanner_json(payload)
    assert findings[0].primary_url == "https://example.com/advisory"


# ---------- semgrep metadata branches ----------

def test_semgrep_severity_from_metadata():
    """_severity: falls back to metadata.severity when extra.severity missing (line 10)."""
    payload = {
        "results": [
            {
                "check_id": "python.security.audit",
                "path": "app.py",
                "extra": {"metadata": {"severity": "HIGH"}, "message": "Issue"},
            }
        ]
    }
    findings = parse_semgrep_json(payload)
    assert findings[0].severity == "HIGH"


def test_semgrep_primary_url_from_metadata_references():
    """_primary_url: returns first URL from metadata.references list (lines 17-19)."""
    payload = {
        "results": [
            {
                "check_id": "python.security.audit",
                "path": "app.py",
                "extra": {
                    "severity": "MEDIUM",
                    "message": "Issue",
                    "metadata": {"references": ["https://example.com/rule"]},
                },
            }
        ]
    }
    findings = parse_semgrep_json(payload)
    assert findings[0].primary_url == "https://example.com/rule"


# ---------- tfsec start_line branch ----------

def test_tfsec_title_includes_start_line():
    """Title is decorated with filename:start_line when start_line is an int (line 16)."""
    payload = {
        "results": [
            {
                "rule_id": "AWS001",
                "description": "S3 bucket is publicly accessible",
                "severity": "HIGH",
                "location": {"filename": "main.tf", "start_line": 42},
            }
        ]
    }
    findings = parse_tfsec_json(payload)
    assert "main.tf:42" in findings[0].title
