import json
import os
import runpy
import datetime as dt
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from sec_report_kit.cli import _parse_modified_since, _parse_modified_until, _write_report, app

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

SAFETY_PAYLOAD = {
    "report_meta": {"scan_target": "environment"},
    "vulnerabilities": [
        {
            "vulnerability_id": "67890",
            "package_name": "urllib3",
            "analyzed_version": "1.26.0",
            "fixed_versions": ["1.26.19"],
            "severity": "high",
            "advisory": "Example Safety advisory",
            "more_info_url": "https://example.com/safety/67890",
        }
    ],
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

SEMGREP_PAYLOAD = {
    "results": [
        {
            "check_id": "python.lang.security.audit",
            "path": "app.py",
            "extra": {"severity": "HIGH", "message": "Issue"},
        }
    ]
}

CODEQL_PAYLOAD = {
    "runs": [
        {
            "tool": {"driver": {"rules": [{"id": "py/sql-injection", "shortDescription": {"text": "SQL injection"}}]}},
            "results": [{"ruleId": "py/sql-injection", "level": "error", "message": {"text": "Issue"}}],
        }
    ]
}

TRUFFLEHOG_NDJSON = '{"DetectorName":"AWS","SourceName":"repo","Verified":true}\n'


def test_render_trivy_command(tmp_path):
    input_file = tmp_path / "trivy.json"
    input_file.write_text(json.dumps(TRIVY_PAYLOAD))
    output_file = tmp_path / "report.html"

    result = runner.invoke(
        app,
        [
            "render",
            "trivy",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--source",
            "container-scan",
            "--target",
            "myimage:1",
        ],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    html = output_file.read_text()
    assert '<div class="meta">Source: <strong>container-scan</strong> | Target: <strong>myimage:1</strong>' in html
    assert "CVE-2024-0001" in html


def test_render_trivy_command_with_utf8_bom_input(tmp_path):
    input_file = tmp_path / "trivy-bom.json"
    input_file.write_text(json.dumps(TRIVY_PAYLOAD), encoding="utf-8-sig")
    output_file = tmp_path / "report-bom.html"

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


def test_render_safety_command(tmp_path):
    input_file = tmp_path / "safety.json"
    input_file.write_text(json.dumps(SAFETY_PAYLOAD))
    output_file = tmp_path / "safety.html"

    result = runner.invoke(
        app,
        ["render", "safety", "--input", str(input_file), "--output", str(output_file), "--target", "requirements.txt"],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert "urllib3" in output_file.read_text()


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


def test_render_auto_command_detects_safety(tmp_path):
    input_file = tmp_path / "safety.json"
    input_file.write_text(json.dumps(SAFETY_PAYLOAD))
    output_file = tmp_path / "report.html"

    result = runner.invoke(
        app,
        ["render", "auto", "--input", str(input_file), "--output", str(output_file)],
    )
    assert result.exit_code == 0
    assert "Detected source type: safety" in result.output


def test_render_bandit_command(tmp_path):
    input_file = tmp_path / "bandit.json"
    input_file.write_text(json.dumps(BANDIT_PAYLOAD))
    output_file = tmp_path / "bandit.html"

    result = runner.invoke(
        app,
        ["render", "bandit", "--input", str(input_file), "--output", str(output_file), "--target", "src"],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert "B101" in output_file.read_text()


def test_render_gitleaks_command(tmp_path):
    input_file = tmp_path / "gitleaks.json"
    input_file.write_text(json.dumps(GITLEAKS_PAYLOAD))
    output_file = tmp_path / "gitleaks.html"

    result = runner.invoke(
        app,
        ["render", "gitleaks", "--input", str(input_file), "--output", str(output_file), "--target", "repo"],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert "generic-api-key" in output_file.read_text()


def test_render_semgrep_command(tmp_path):
    input_file = tmp_path / "semgrep.json"
    input_file.write_text(json.dumps(SEMGREP_PAYLOAD))
    output_file = tmp_path / "semgrep.html"

    result = runner.invoke(
        app,
        ["render", "semgrep", "--input", str(input_file), "--output", str(output_file), "--target", "repo"],
    )
    assert result.exit_code == 0
    assert output_file.exists()


def test_render_codeql_command(tmp_path):
    input_file = tmp_path / "codeql.sarif.json"
    input_file.write_text(json.dumps(CODEQL_PAYLOAD))
    output_file = tmp_path / "codeql.html"

    result = runner.invoke(
        app,
        ["render", "codeql", "--input", str(input_file), "--output", str(output_file), "--target", "repo"],
    )
    assert result.exit_code == 0
    assert output_file.exists()


def test_render_trufflehog_accepts_ndjson(tmp_path):
    input_file = tmp_path / "trufflehog.json"
    input_file.write_text(TRUFFLEHOG_NDJSON)
    output_file = tmp_path / "trufflehog.html"

    result = runner.invoke(
        app,
        [
            "render",
            "trufflehog",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--source",
            "secret-scan",
            "--target",
            "repo",
        ],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    html = output_file.read_text()
    assert '<div class="meta">Source: <strong>secret-scan</strong> | Target: <strong>repo</strong>' in html


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


def test_version_flag_outputs_package_version():
    from sec_report_kit import __version__

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"sec-report-kit {__version__}" in result.output


def test_main_calls_app(monkeypatch):
    """Covers main() -> app() (cli.py line 89)."""
    import pytest
    monkeypatch.setattr("sys.argv", ["srk", "--help"])
    from sec_report_kit.cli import main
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0


def test_main_help_does_not_print_banner(monkeypatch, capsys):
    import pytest

    monkeypatch.setattr("sys.argv", ["srk", "--help"])
    from sec_report_kit.cli import main

    with pytest.raises(SystemExit) as exc:
        main()

    captured = capsys.readouterr()
    assert exc.value.code == 0
    assert "____  _____" not in captured.out


def test_main_version_does_not_print_banner(monkeypatch, capsys):
    import pytest
    from sec_report_kit import __version__

    monkeypatch.setattr("sys.argv", ["srk", "--version"])
    from sec_report_kit.cli import main

    with pytest.raises(SystemExit) as exc:
        main()

    captured = capsys.readouterr()
    assert exc.value.code == 0
    assert f"sec-report-kit {__version__}" in captured.out
    assert "____  _____" not in captured.out


# Cover cli.py line 195: except ValueError as exc: (in _parse_modified_since)
def test_parse_modified_since_invalid_value():
    from sec_report_kit.cli import _parse_modified_since
    import pytest
    with pytest.raises(Exception) as excinfo:
        _parse_modified_since("not-a-date")
    assert "Use ISO date/datetime" in str(excinfo.value)

# Cover cli.py line 368: except Exception as exc: (in render_consolidated)
def test_render_consolidated_skips_invalid_file(tmp_path):
    from sec_report_kit.cli import app
    from typer.testing import CliRunner
    runner = CliRunner()
    reports_dir = tmp_path / "security_reports"
    reports_dir.mkdir()
    # Write a file that will cause detect_source_type to raise ValueError
    (reports_dir / "bad.json").write_text("{}")
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "render",
            "consolidated",
            "--input",
            str(reports_dir),
            "--output",
            str(output_dir),
        ],
    )
    assert result.exit_code == 0
    assert "Skipping bad.json" in result.output


def test_main_module_runs():
    """Covers sec_report_kit/__main__.py by running the module as __main__."""
    with patch("sec_report_kit.cli.main") as mock_main:
        runpy.run_module("sec_report_kit.__main__", run_name="__main__")
    mock_main.assert_called_once()


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

TFSEC_PAYLOAD = {
    "results": [
        {
            "rule_id": "AWS001",
            "description": "S3 bucket publicly accessible",
            "severity": "HIGH",
            "location": {"filename": "main.tf"},
        }
    ]
}


def test_load_json_ndjson_branch(tmp_path):
    """_load_json falls back to NDJSON parsing when content is not valid JSON (lines 35-43).

    Uses two JSON objects on separate lines (true NDJSON, invalid as a single JSON document)
    with a blank line in between to exercise the 'continue' on blank lines.
    """
    ndjson_content = (
        '{"DetectorName":"AWS","SourceName":"repo","Verified":true}\n'
        '\n'
        '{"DetectorName":"GitHub","SourceName":"repo","Verified":false}\n'
    )
    input_file = tmp_path / "trufflehog.ndjson"
    input_file.write_text(ndjson_content)
    output_file = tmp_path / "report.html"

    result = runner.invoke(
        app,
        ["render", "trufflehog", "--input", str(input_file), "--output", str(output_file), "--target", "repo"],
    )
    assert result.exit_code == 0
    assert output_file.exists()


def test_render_osv_scanner_command(tmp_path):
    input_file = tmp_path / "osv.json"
    input_file.write_text(json.dumps(OSV_SCANNER_PAYLOAD))
    output_file = tmp_path / "osv.html"

    result = runner.invoke(
        app,
        ["render", "osv-scanner", "--input", str(input_file), "--output", str(output_file), "--target", "requirements.txt"],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert "requests" in output_file.read_text()


def test_render_checkov_command(tmp_path):
    input_file = tmp_path / "checkov.json"
    input_file.write_text(json.dumps(CHECKOV_PAYLOAD))
    output_file = tmp_path / "checkov.html"

    result = runner.invoke(
        app,
        ["render", "checkov", "--input", str(input_file), "--output", str(output_file), "--target", "terraform"],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert "CKV_AWS_1" in output_file.read_text()


def test_render_tfsec_command(tmp_path):
    input_file = tmp_path / "tfsec.json"
    input_file.write_text(json.dumps(TFSEC_PAYLOAD))
    output_file = tmp_path / "tfsec.html"

    result = runner.invoke(
        app,
        ["render", "tfsec", "--input", str(input_file), "--output", str(output_file), "--target", "terraform"],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert "AWS001" in output_file.read_text()


def test_render_consolidated_command_from_directory(tmp_path):
    reports_dir = tmp_path / "security_reports"
    reports_dir.mkdir()

    trivy_file = reports_dir / "trivy.json"
    trivy_file.write_text(json.dumps(TRIVY_PAYLOAD))

    bandit_file = reports_dir / "bandit.json"
    bandit_file.write_text(json.dumps(BANDIT_PAYLOAD))

    # Non-report content should be skipped safely.
    ignored_file = reports_dir / "notes.json"
    ignored_file.write_text(json.dumps({"hello": "world"}))

    output_dir = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "render",
            "consolidated",
            "--input",
            str(reports_dir),
            "--output",
            str(output_dir),
            "--target",
            "repo-root",
        ],
    )

    output_file = output_dir / "consolidated-security-report.html"
    bandit_report = output_dir / "bandit-report.html"
    trivy_report = output_dir / "trivy-report.html"
    assert result.exit_code == 0
    assert output_file.exists()
    assert bandit_report.exists()
    assert trivy_report.exists()
    html = output_file.read_text()
    assert "Security Audit Consolidated Dashboard" in html
    assert "Reports available:" in html
    assert "Target: repo-root" in html
    assert "Bandit" in html
    assert "Trivy" in html
    assert 'src="bandit-report.html"' in html
    assert 'src="trivy-report.html"' in html


def test_render_consolidated_command_empty_or_unsupported_directory(tmp_path):
    reports_dir = tmp_path / "security_reports"
    reports_dir.mkdir()
    (reports_dir / "unsupported.json").write_text(json.dumps({"invalid": True}))

    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        ["render", "consolidated", "--input", str(reports_dir), "--output", str(output_dir)],
    )

    output_file = output_dir / "consolidated-security-report.html"
    assert result.exit_code == 0
    assert output_file.exists()
    html = output_file.read_text()
    assert "Security Audit Consolidated Dashboard" in html
    assert "Total Findings" in html
    assert "Reports available:" in html


def test_render_consolidated_command_modified_since_filters_candidates(tmp_path):
    reports_dir = tmp_path / "security_reports"
    reports_dir.mkdir()

    old_file = reports_dir / "bandit.json"
    old_file.write_text(json.dumps(BANDIT_PAYLOAD))
    old_stamp = dt.datetime(2026, 5, 2, 9, 0, 0).timestamp()
    os.utime(old_file, (old_stamp, old_stamp))

    new_file = reports_dir / "trivy.json"
    new_file.write_text(json.dumps(TRIVY_PAYLOAD))
    new_stamp = dt.datetime(2026, 5, 10, 9, 0, 0).timestamp()
    os.utime(new_file, (new_stamp, new_stamp))

    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "render",
            "consolidated",
            "--input",
            str(reports_dir),
            "--output",
            str(output_dir),
            "--target",
            "repo-root",
            "--modified-since",
            "2026-05-05",
        ],
    )

    assert result.exit_code == 0
    assert "Included trivy.json" in result.output
    assert "Included bandit.json" not in result.output
    assert "Files included: 1" in result.output
    assert (output_dir / "trivy-report.html").exists()
    assert not (output_dir / "bandit-report.html").exists()


def test_render_consolidated_command_modified_until_filters_candidates(tmp_path):
    reports_dir = tmp_path / "security_reports"
    reports_dir.mkdir()

    old_file = reports_dir / "bandit.json"
    old_file.write_text(json.dumps(BANDIT_PAYLOAD))
    old_stamp = dt.datetime(2026, 5, 2, 9, 0, 0).timestamp()
    os.utime(old_file, (old_stamp, old_stamp))

    new_file = reports_dir / "trivy.json"
    new_file.write_text(json.dumps(TRIVY_PAYLOAD))
    new_stamp = dt.datetime(2026, 5, 10, 9, 0, 0).timestamp()
    os.utime(new_file, (new_stamp, new_stamp))

    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "render",
            "consolidated",
            "--input",
            str(reports_dir),
            "--output",
            str(output_dir),
            "--modified-until",
            "2026-05-05",
        ],
    )

    assert result.exit_code == 0
    assert "Included bandit.json" in result.output
    assert "Included trivy.json" not in result.output
    assert "Modified until filter: 2026-05-05" in result.output
    assert "Files included: 1" in result.output


def test_render_consolidated_command_date_range_filters_candidates(tmp_path):
    reports_dir = tmp_path / "security_reports"
    reports_dir.mkdir()

    old_file = reports_dir / "bandit.json"
    old_file.write_text(json.dumps(BANDIT_PAYLOAD))
    old_stamp = dt.datetime(2026, 5, 2, 9, 0, 0).timestamp()
    os.utime(old_file, (old_stamp, old_stamp))

    middle_file = reports_dir / "gitleaks.json"
    middle_file.write_text(json.dumps(GITLEAKS_PAYLOAD))
    middle_stamp = dt.datetime(2026, 5, 6, 9, 0, 0).timestamp()
    os.utime(middle_file, (middle_stamp, middle_stamp))

    new_file = reports_dir / "trivy.json"
    new_file.write_text(json.dumps(TRIVY_PAYLOAD))
    new_stamp = dt.datetime(2026, 5, 10, 9, 0, 0).timestamp()
    os.utime(new_file, (new_stamp, new_stamp))

    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "render",
            "consolidated",
            "--input",
            str(reports_dir),
            "--output",
            str(output_dir),
            "--modified-since",
            "2026-05-05",
            "--modified-until",
            "2026-05-07",
        ],
    )

    assert result.exit_code == 0
    assert "Included gitleaks.json" in result.output
    assert "Included bandit.json" not in result.output
    assert "Included trivy.json" not in result.output
    assert "Files included: 1" in result.output


def test_render_consolidated_command_limit_uses_most_recent_files(tmp_path):
    reports_dir = tmp_path / "security_reports"
    reports_dir.mkdir()

    oldest = reports_dir / "bandit.json"
    oldest.write_text(json.dumps(BANDIT_PAYLOAD))
    oldest_stamp = dt.datetime(2026, 5, 1, 8, 0, 0).timestamp()
    os.utime(oldest, (oldest_stamp, oldest_stamp))

    middle = reports_dir / "gitleaks.json"
    middle.write_text(json.dumps(GITLEAKS_PAYLOAD))
    middle_stamp = dt.datetime(2026, 5, 3, 8, 0, 0).timestamp()
    os.utime(middle, (middle_stamp, middle_stamp))

    newest = reports_dir / "trivy.json"
    newest.write_text(json.dumps(TRIVY_PAYLOAD))
    newest_stamp = dt.datetime(2026, 5, 5, 8, 0, 0).timestamp()
    os.utime(newest, (newest_stamp, newest_stamp))

    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "render",
            "consolidated",
            "--input",
            str(reports_dir),
            "--output",
            str(output_dir),
            "--limit",
            "2",
        ],
    )

    assert result.exit_code == 0
    assert "Included trivy.json" in result.output
    assert "Included gitleaks.json" in result.output
    assert "Included bandit.json" not in result.output
    assert "File limit: 2" in result.output
    assert "Files included: 2" in result.output


def test_generate_consolidated_wrapper_invokes_cli(monkeypatch, tmp_path):
    input_dir = tmp_path / "reports"
    output_dir = tmp_path / "out"
    input_dir.mkdir()
    monkeypatch.setattr(
        "sys.argv",
        [
            "generate_consolidated_security_report.py",
            "--input",
            str(input_dir),
            "--output",
            str(output_dir),
            "--target",
            "repo-root",
            "--modified-since",
            "today",
            "--modified-until",
            "today",
            "--limit",
            "3",
        ],
    )

    with patch("sec_report_kit.generate_consolidated_security_report.render_consolidated") as mock_render:
        from sec_report_kit.generate_consolidated_security_report import main as wrapper_main

        exit_code = wrapper_main()

    assert exit_code == 0
    mock_render.assert_called_once_with(
        input=input_dir,
        output=output_dir,
        target="repo-root",
        modified_since="today",
        modified_until="today",
        limit=3,
    )


def test_detect_source_type_raises_value_error():
    from sec_report_kit.parsers import detect_source_type

    with pytest.raises(ValueError):
        detect_source_type({"foo": "bar"})


def test_detect_source_type_bandit_fallback_branch():
    from sec_report_kit.parsers import detect_source_type

    assert detect_source_type({"results": [{}]}) == "bandit"


def test_write_consolidated_tool_reports_skips_unknown_parser(tmp_path):
    from sec_report_kit.cli import _write_consolidated_tool_reports

    findings_by_parser = {"unknown-parser": [{"dummy": 1}]}
    _write_consolidated_tool_reports(tmp_path, "target", findings_by_parser)

    assert not any(tmp_path.iterdir())


def test_render_consolidated_defaults_output_to_input(tmp_path):
    reports_dir = tmp_path / "security_reports"
    reports_dir.mkdir()
    (reports_dir / "trivy.json").write_text(json.dumps(TRIVY_PAYLOAD))

    result = runner.invoke(
        app,
        [
            "render",
            "consolidated",
            "--input",
            str(reports_dir),
        ],
    )

    assert result.exit_code == 0
    assert (reports_dir / "consolidated-security-report.html").exists()

def test_parse_modified_since_supports_named_ranges():
    today = _parse_modified_since("today")
    yesterday = _parse_modified_since("yesterday")
    last_week = _parse_modified_since("last-week")

    assert today.hour == 0
    assert today.minute == 0
    assert yesterday.hour == 0
    assert yesterday.minute == 0
    assert yesterday < today
    assert last_week < today


def test_parse_modified_since_supports_iso_inputs_and_raises_for_invalid():
    naive = _parse_modified_since("2026-05-10")
    aware = _parse_modified_since("2026-05-10T09:00:00Z")

    assert naive.year == 2026
    assert naive.month == 5
    assert naive.day == 10
    assert naive.tzinfo is not None
    assert aware.tzinfo is not None

    import typer

    with pytest.raises(typer.BadParameter):
        _parse_modified_since("not-a-date")


def test_parse_modified_until_supports_named_and_date_only_inputs():
    today = _parse_modified_until("today")
    yesterday = _parse_modified_until("yesterday")
    date_only = _parse_modified_until("2026-05-10")
    datetime_value = _parse_modified_until("2026-05-10T09:15:00")

    assert today.hour == 23
    assert today.minute == 59
    assert today.second == 59
    assert today.microsecond == 999999
    assert yesterday.hour == 23
    assert yesterday.minute == 59
    assert date_only.hour == 23
    assert date_only.minute == 59
    assert datetime_value.hour == 9
    assert datetime_value.minute == 15


def test_generate_consolidated_wrapper_module_main(monkeypatch, tmp_path):
    input_dir = tmp_path / "reports"
    output_dir = tmp_path / "out"
    input_dir.mkdir()

    monkeypatch.setattr(
        "sys.argv",
        [
            "generate_consolidated_security_report.py",
            "--input",
            str(input_dir),
            "--output",
            str(output_dir),
        ],
    )

    with patch("sec_report_kit.cli.render_consolidated") as mock_render:
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("sec_report_kit.generate_consolidated_security_report", run_name="__main__")

    assert exc.value.code == 0
    mock_render.assert_called_once()


def test_consolidated_helper_scripts_exist():
    assert Path("scripts/render_consolidated_html.bat").exists()
    assert Path("scripts/render_consolidated_html.sh").exists()
