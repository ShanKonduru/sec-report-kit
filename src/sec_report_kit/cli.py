from __future__ import annotations

import json
from pathlib import Path

import typer

from sec_report_kit.parsers import detect_source_type
from sec_report_kit.parsers.pip_audit import parse_pip_audit_json
from sec_report_kit.parsers.trivy import parse_trivy_json
from sec_report_kit.report.html_renderer import render_html_report
from sec_report_kit.services.summarize import count_by_severity, sort_findings

app = typer.Typer(help="Security report kit CLI")
render_app = typer.Typer(help="Render HTML reports")
mcp_app = typer.Typer(help="MCP server commands")
app.add_typer(render_app, name="render")
app.add_typer(mcp_app, name="mcp")


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_report(source_label: str, target_ref: str, input_path: Path, output_path: Path, parser: str) -> None:
    payload = _load_json(input_path)
    if parser == "auto":
        parser = detect_source_type(payload)
        typer.echo(f"[INFO] Detected source type: {parser}")
    if parser == "trivy":
        findings = parse_trivy_json(payload)
    elif parser == "pip-audit":
        findings = parse_pip_audit_json(payload)
    else:
        raise typer.BadParameter(f"Unsupported parser: {parser}")

    findings = sort_findings(findings)
    counts = count_by_severity(findings)
    report_html = render_html_report(target_ref=target_ref, source_label=source_label, findings=findings, counts=counts)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_html, encoding="utf-8")

    typer.echo(f"[OK] Report generated: {output_path}")
    typer.echo(f"[INFO] Total findings: {len(findings)}")
    typer.echo(f"[INFO] Severity counts: {counts}")


@render_app.command("trivy")
def render_trivy(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option(..., "--target", help="Scanned image or artifact reference"),
) -> None:
    """Render HTML report from Trivy JSON output."""
    _write_report("trivy", target, input, output, parser="trivy")


@render_app.command("pip-audit")
def render_pip_audit(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("python-environment", "--target", help="Python environment target label"),
) -> None:
    """Render HTML report from pip-audit JSON output."""
    _write_report("pip-audit", target, input, output, parser="pip-audit")


@render_app.command("auto")
def render_auto(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("unknown", "--target", help="Scanned image or artifact reference"),
) -> None:
    """Auto-detect input format (Trivy or pip-audit) and render HTML report."""
    _write_report("auto", target, input, output, parser="auto")


@mcp_app.command("serve")
def serve_mcp(
    transport: str = typer.Option("stdio", "--transport", help="MCP transport (currently stdio)")
) -> None:
    """Run the MCP server."""
    from sec_report_kit.mcp.server import run_server

    run_server(transport=transport)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
