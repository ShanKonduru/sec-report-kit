import json
import runpy
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from sec_report_kit.cli import _write_report, app

runner = CliRunner()

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


def test_render_trivy_command(tmp_path):
    input_file = tmp_path / "trivy.json"
    input_file.write_text(json.dumps(TRIVY_PAYLOAD))
    output_file = tmp_path / "report.html"

    result = runner.invoke(
        app,
        ["render", "trivy", "--input", str(input_file), "--output", str(output_file), "--target", "myimage:1"],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert "CVE-2024-0001" in output_file.read_text()


def test_render_pip_audit_command(tmp_path):
    input_file = tmp_path / "pip-audit.json"
    input_file.write_text(json.dumps(PIP_AUDIT_PAYLOAD))
    output_file = tmp_path / "report.html"

    result = runner.invoke(
        app,
        ["render", "pip-audit", "--input", str(input_file), "--output", str(output_file), "--target", "requirements.txt"],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert "requests" in output_file.read_text()


def test_render_auto_command_detects_trivy(tmp_path):
    input_file = tmp_path / "trivy.json"
    input_file.write_text(json.dumps(TRIVY_PAYLOAD))
    output_file = tmp_path / "report.html"

    result = runner.invoke(
        app,
        ["render", "auto", "--input", str(input_file), "--output", str(output_file), "--target", "myimage:1"],
    )
    assert result.exit_code == 0
    assert "Detected source type: trivy" in result.output


def test_render_auto_command_detects_pip_audit(tmp_path):
    input_file = tmp_path / "pip.json"
    input_file.write_text(json.dumps(PIP_AUDIT_PAYLOAD))
    output_file = tmp_path / "report.html"

    result = runner.invoke(
        app,
        ["render", "auto", "--input", str(input_file), "--output", str(output_file)],
    )
    assert result.exit_code == 0
    assert "Detected source type: pip-audit" in result.output


def test_write_report_unsupported_parser_raises(tmp_path):
    input_file = tmp_path / "data.json"
    input_file.write_text(json.dumps(TRIVY_PAYLOAD))
    output_file = tmp_path / "out.html"

    import typer
    with pytest.raises(typer.BadParameter):
        _write_report("test", "target", input_file, output_file, parser="unknown-parser")


def test_serve_mcp_command():
    """Covers the serve_mcp CLI command body (cli.py lines 83-85)."""
    with patch("sec_report_kit.mcp.server.run_server") as mock_run:
        result = runner.invoke(app, ["mcp", "serve", "--transport", "stdio"])
    assert result.exit_code == 0
    mock_run.assert_called_once_with(transport="stdio")


def test_main_calls_app(monkeypatch):
    """Covers main() -> app() (cli.py line 89)."""
    monkeypatch.setattr("sys.argv", ["srk", "--help"])
    from sec_report_kit.cli import main
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0


def test_main_module_runs():
    """Covers sec_report_kit/__main__.py by running the module as __main__."""
    with patch("sec_report_kit.cli.main") as mock_main:
        runpy.run_module("sec_report_kit.__main__", run_name="__main__")
    mock_main.assert_called_once()
