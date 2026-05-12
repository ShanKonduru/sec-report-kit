import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import sec_report_kit.mcp.server as srv

TRIVY_PAYLOAD = {
    "Results": [
        {
            "Target": "myimage:1",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "Severity": "HIGH",
                    "VulnerabilityID": "CVE-2024-0001",
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

PIP_AUDIT_PAYLOAD = {
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

BANDIT_PAYLOAD = {
    "results": [
        {
            "filename": "src/app.py",
            "issue_severity": "HIGH",
            "issue_text": "Use of assert detected.",
            "test_id": "B101",
            "test_name": "assert_used",
        }
    ]
}

GITLEAKS_PAYLOAD = [
    {
        "RuleID": "generic-api-key",
        "Description": "Hardcoded API key",
        "File": "src/settings.py",
        "Fingerprint": "src/settings.py:generic-api-key:42",
    }
]

CODEQL_PAYLOAD = {
    "runs": [
        {
            "tool": {"driver": {"rules": [{"id": "py/sql-injection", "shortDescription": {"text": "SQL injection"}}]}},
            "results": [{"ruleId": "py/sql-injection", "level": "error", "message": {"text": "Issue"}}],
        }
    ]
}


class _CaptureMCP:
    """Fake FastMCP that captures decorated tool functions for direct testing."""
    def __init__(self, name):
        self._tools: dict = {}

    def tool(self):
        def decorator(fn):
            self._tools[fn.__name__] = fn
            return fn
        return decorator

    def run(self, transport="stdio"):
        pass


def _build_with_capture():
    with patch("mcp.server.fastmcp.FastMCP", _CaptureMCP):
        return srv.build_server()


# ---------- _load_payload ----------

def test_load_payload_trivy(tmp_path):
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(TRIVY_PAYLOAD))
    findings = srv._load_payload("trivy", str(p))
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "CVE-2024-0001"


def test_load_payload_pip_audit(tmp_path):
    p = tmp_path / "pip.json"
    p.write_text(json.dumps(PIP_AUDIT_PAYLOAD))
    findings = srv._load_payload("pip-audit", str(p))
    assert len(findings) == 1
    assert findings[0].package == "requests"


def test_load_payload_auto_detects_trivy(tmp_path):
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(TRIVY_PAYLOAD))
    findings = srv._load_payload("auto", str(p))
    assert findings[0].vulnerability_id == "CVE-2024-0001"


def test_load_payload_bandit(tmp_path):
    p = tmp_path / "bandit.json"
    p.write_text(json.dumps(BANDIT_PAYLOAD))
    findings = srv._load_payload("bandit", str(p))
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "B101"


def test_load_payload_gitleaks(tmp_path):
    p = tmp_path / "gitleaks.json"
    p.write_text(json.dumps(GITLEAKS_PAYLOAD))
    findings = srv._load_payload("gitleaks", str(p))
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "generic-api-key"


def test_load_payload_codeql(tmp_path):
    p = tmp_path / "codeql.sarif.json"
    p.write_text(json.dumps(CODEQL_PAYLOAD))
    findings = srv._load_payload("codeql", str(p))
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "py/sql-injection"


def test_load_payload_trufflehog_ndjson(tmp_path):
    p = tmp_path / "trufflehog.json"
    p.write_text('{"DetectorName":"AWS","SourceName":"repo","Verified":true}\n')
    findings = srv._load_payload("trufflehog", str(p))
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "AWS"


def test_load_payload_invalid_source_type_raises(tmp_path):
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(TRIVY_PAYLOAD))
    with pytest.raises(ValueError):
        srv._load_payload("unsupported", str(p))


# ---------- build_server / MCP tools ----------

def test_build_server_returns_mcp_instance():
    mcp = _build_with_capture()
    assert isinstance(mcp, _CaptureMCP)
    assert "summarize_json" in mcp._tools
    assert "render_report_from_json" in mcp._tools
    assert "validate_input" in mcp._tools


def test_mcp_tool_summarize_json(tmp_path):
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(TRIVY_PAYLOAD))
    mcp = _build_with_capture()
    result = mcp._tools["summarize_json"](source_type="trivy", input_path=str(p))
    assert result["total"] == 1
    assert "HIGH" in result["counts"]


def test_mcp_tool_render_report_from_json(tmp_path):
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(TRIVY_PAYLOAD))
    out = tmp_path / "report.html"
    mcp = _build_with_capture()
    result = mcp._tools["render_report_from_json"](
        source_type="trivy",
        input_path=str(p),
        output_path=str(out),
        target="myimage:1",
    )
    assert result["total"] == 1
    assert out.exists()


def test_mcp_tool_validate_input(tmp_path):
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(TRIVY_PAYLOAD))
    mcp = _build_with_capture()
    result = mcp._tools["validate_input"](source_type="trivy", input_path=str(p))
    assert result["valid"] is True
    assert result["total_findings"] == 1


# ---------- run_server ----------

def test_run_server_invalid_transport_raises(tmp_path):
    with pytest.raises(ValueError, match="Only stdio transport is currently supported"):
        with patch("sec_report_kit.mcp.server.build_server", return_value=_CaptureMCP("x")):
            srv.run_server(transport="http")


def test_run_server_stdio_calls_run():
    fake_mcp = MagicMock()
    with patch("sec_report_kit.mcp.server.build_server", return_value=fake_mcp):
        srv.run_server(transport="stdio")
    fake_mcp.run.assert_called_once_with(transport="stdio")


# ---------- _load_payload additional source types ----------

SEMGREP_PAYLOAD = {
    "version": "1.0",
    "results": [
        {
            "check_id": "python.lang.security.audit",
            "path": "app.py",
            "extra": {"severity": "HIGH", "message": "Issue"},
        }
    ],
}

OSV_SCANNER_PAYLOAD = {
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

CHECKOV_PAYLOAD = {
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

TFSEC_PAYLOAD_SRV = {
    "results": [
        {"rule_id": "AWS001", "description": "Issue", "severity": "HIGH"}
    ]
}


def test_load_payload_ndjson_branch(tmp_path):
    """_load_payload falls back to NDJSON parsing (lines 26-27).

    Two objects on separate lines make the content invalid as a single JSON document,
    forcing the json.JSONDecodeError fallback branch.
    """
    ndjson = (
        '{"DetectorName":"AWS","SourceName":"repo","Verified":true}\n'
        '{"DetectorName":"GitHub","SourceName":"repo","Verified":false}\n'
    )
    p = tmp_path / "trufflehog.ndjson"
    p.write_text(ndjson)
    findings = srv._load_payload("trufflehog", str(p))
    assert len(findings) == 2
    assert findings[0].vulnerability_id == "AWS"


def test_load_payload_semgrep(tmp_path):
    """Covers semgrep branch in _load_payload (line 39)."""
    p = tmp_path / "semgrep.json"
    p.write_text(json.dumps(SEMGREP_PAYLOAD))
    findings = srv._load_payload("semgrep", str(p))
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "python.lang.security.audit"


def test_load_payload_osv_scanner(tmp_path):
    """Covers osv-scanner branch in _load_payload (line 43)."""
    p = tmp_path / "osv.json"
    p.write_text(json.dumps(OSV_SCANNER_PAYLOAD))
    findings = srv._load_payload("osv-scanner", str(p))
    assert len(findings) == 1
    assert findings[0].package == "requests"


def test_load_payload_checkov(tmp_path):
    """Covers checkov branch in _load_payload (line 45)."""
    p = tmp_path / "checkov.json"
    p.write_text(json.dumps(CHECKOV_PAYLOAD))
    findings = srv._load_payload("checkov", str(p))
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "CKV_AWS_1"


def test_load_payload_tfsec(tmp_path):
    """Covers tfsec branch in _load_payload (line 47)."""
    p = tmp_path / "tfsec.json"
    p.write_text(json.dumps(TFSEC_PAYLOAD_SRV))
    findings = srv._load_payload("tfsec", str(p))
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "AWS001"
