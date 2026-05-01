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
