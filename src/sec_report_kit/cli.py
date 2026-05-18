from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import typer

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
from sec_report_kit.report.html_renderer import render_consolidated_dashboard_report, render_html_report
from sec_report_kit.services.summarize import count_by_severity, sort_findings

app = typer.Typer(help="Security report kit CLI")
render_app = typer.Typer(help="Render HTML reports")
mcp_app = typer.Typer(help="MCP server commands")
app.add_typer(render_app, name="render")
app.add_typer(mcp_app, name="mcp")


_CONSOLIDATED_TOOL_OUTPUT_FILES = {
    "pip-audit": "pip-audit-report.html",
    "trivy": "trivy-report.html",
    "gitleaks": "gitleaks-report.html",
    "safety": "safety-report.html",
    "bandit": "bandit-report.html",
    "semgrep": "semgrep-report.html",
    "codeql": "codeql-report.html",
    "osv-scanner": "osv-scanner-report.html",
    "checkov": "checkov-report.html",
    "tfsec": "tfsec-report.html",
    "trufflehog": "trufflehog-report.html",
}


def _parse_modified_since(value: str) -> dt.datetime:
    local_tz = dt.datetime.now().astimezone().tzinfo or dt.timezone.utc
    now = dt.datetime.now(local_tz)
    normalized = value.strip().lower()

    if normalized == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if normalized == "yesterday":
        return (now - dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    if normalized in {"last-week", "last-7-days"}:
        return now - dt.timedelta(days=7)

    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:  # pragma: no cover
        raise typer.BadParameter(
            "Use ISO date/datetime or one of: today, yesterday, last-week, last-7-days"
        ) from exc

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=local_tz)
    return parsed.astimezone(local_tz)


def _parse_modified_until(value: str) -> dt.datetime:
    local_tz = dt.datetime.now().astimezone().tzinfo or dt.timezone.utc
    normalized = value.strip().lower()

    if normalized == "today":
        return dt.datetime.now(local_tz).replace(hour=23, minute=59, second=59, microsecond=999999)
    if normalized == "yesterday":
        return (dt.datetime.now(local_tz) - dt.timedelta(days=1)).replace(
            hour=23,
            minute=59,
            second=59,
            microsecond=999999,
        )

    parsed = _parse_modified_since(value)
    if "T" not in value and " " not in value:
        return parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
    return parsed


def _collect_consolidated_candidates(
    input_dir: Path,
    modified_since: str | None,
    modified_until: str | None,
    limit: int | None,
) -> list[Path]:
    candidates = [
        path
        for path in input_dir.iterdir()
        if path.is_file()
        and (
            path.suffix.lower() in {".json", ".sarif", ".ndjson", ".jsonl"}
            or path.name.lower().endswith(".sarif.json")
        )
    ]

    if modified_since:
        cutoff = _parse_modified_since(modified_since)
        candidates = [
            path
            for path in candidates
            if dt.datetime.fromtimestamp(path.stat().st_mtime, tz=cutoff.tzinfo) >= cutoff
        ]

    if modified_until:
        cutoff = _parse_modified_until(modified_until)
        candidates = [
            path
            for path in candidates
            if dt.datetime.fromtimestamp(path.stat().st_mtime, tz=cutoff.tzinfo) <= cutoff
        ]

    candidates.sort(key=lambda path: (-path.stat().st_mtime, path.name.lower()))

    if limit is not None:
        candidates = candidates[:limit]

    return candidates


def _load_json(path: Path) -> Any:
    # Accept both UTF-8 and UTF-8 BOM encoded JSON files.
    raw = path.read_text(encoding="utf-8-sig")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Some scanners emit NDJSON (one JSON object per line).
        items: list[dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
        return items


def _parse_findings(payload: Any, parser: str):
    if parser == "trivy":
        return parse_trivy_json(payload)
    if parser == "pip-audit":
        return parse_pip_audit_json(payload)
    if parser == "safety":
        return parse_safety_json(payload)
    if parser == "bandit":
        return parse_bandit_json(payload)
    if parser == "gitleaks":
        return parse_gitleaks_json(payload)
    if parser == "semgrep":
        return parse_semgrep_json(payload)
    if parser == "codeql":
        return parse_codeql_json(payload)
    if parser == "osv-scanner":
        return parse_osv_scanner_json(payload)
    if parser == "checkov":
        return parse_checkov_json(payload)
    if parser == "tfsec":
        return parse_tfsec_json(payload)
    if parser == "trufflehog":
        return parse_trufflehog_json(payload)
    raise typer.BadParameter(f"Unsupported parser: {parser}")


def _write_report(source_label: str, target_ref: str, input_path: Path, output_path: Path, parser: str) -> None:
    payload = _load_json(input_path)
    if parser == "auto":
        parser = detect_source_type(payload)
        typer.echo(f"[INFO] Detected source type: {parser}")
    findings = _parse_findings(payload, parser)

    findings = sort_findings(findings)
    counts = count_by_severity(findings)
    report_html = render_html_report(target_ref=target_ref, source_label=source_label, findings=findings, counts=counts)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_html, encoding="utf-8")

    typer.echo(f"[OK] Report generated: {output_path}")
    typer.echo(f"[INFO] Total findings: {len(findings)}")
    typer.echo(f"[INFO] Severity counts: {counts}")


def _write_consolidated_tool_reports(output_dir: Path, target_ref: str, findings_by_parser: dict[str, list[Any]]) -> None:
    for parser, findings in findings_by_parser.items():
        output_name = _CONSOLIDATED_TOOL_OUTPUT_FILES.get(parser)
        if output_name is None:
            continue

        sorted_findings = sort_findings(findings)
        counts = count_by_severity(sorted_findings)
        report_html = render_html_report(
            target_ref=target_ref,
            source_label=parser,
            findings=sorted_findings,
            counts=counts,
        )
        (output_dir / output_name).write_text(report_html, encoding="utf-8")


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


@render_app.command("safety")
def render_safety(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("python-environment", "--target", help="Python environment target label"),
) -> None:
    """Render HTML report from Safety CLI JSON output."""
    _write_report("safety", target, input, output, parser="safety")


@render_app.command("auto")
def render_auto(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("unknown", "--target", help="Scanned image or artifact reference"),
) -> None:
    """Auto-detect supported input format and render HTML report."""
    _write_report("auto", target, input, output, parser="auto")


@render_app.command("bandit")
def render_bandit(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("python-codebase", "--target", help="Codebase target label"),
) -> None:
    """Render HTML report from Bandit JSON output."""
    _write_report("bandit", target, input, output, parser="bandit")


@render_app.command("gitleaks")
def render_gitleaks(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("repository", "--target", help="Repository or scan target label"),
) -> None:
    """Render HTML report from Gitleaks JSON output."""
    _write_report("gitleaks", target, input, output, parser="gitleaks")


@render_app.command("semgrep")
def render_semgrep(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("repository", "--target", help="Repository or scan target label"),
) -> None:
    """Render HTML report from Semgrep JSON output."""
    _write_report("semgrep", target, input, output, parser="semgrep")


@render_app.command("codeql")
def render_codeql(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("repository", "--target", help="Repository or scan target label"),
) -> None:
    """Render HTML report from CodeQL SARIF JSON output."""
    _write_report("codeql", target, input, output, parser="codeql")


@render_app.command("osv-scanner")
def render_osv_scanner(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("dependency-manifest", "--target", help="Dependency manifest target label"),
) -> None:
    """Render HTML report from OSV-Scanner JSON output."""
    _write_report("osv-scanner", target, input, output, parser="osv-scanner")


@render_app.command("checkov")
def render_checkov(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("infrastructure-code", "--target", help="IaC scan target label"),
) -> None:
    """Render HTML report from Checkov JSON output."""
    _write_report("checkov", target, input, output, parser="checkov")


@render_app.command("tfsec")
def render_tfsec(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("infrastructure-code", "--target", help="IaC scan target label"),
) -> None:
    """Render HTML report from tfsec JSON output."""
    _write_report("tfsec", target, input, output, parser="tfsec")


@render_app.command("trufflehog")
def render_trufflehog(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, file_okay=True, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False, file_okay=True),
    target: str = typer.Option("repository", "--target", help="Repository or scan target label"),
) -> None:
    """Render HTML report from TruffleHog JSON output."""
    _write_report("trufflehog", target, input, output, parser="trufflehog")


@render_app.command("consolidated")
def render_consolidated(
    input: Path = typer.Option(
        ...,
        "--input",
        exists=True,
        dir_okay=True,
        file_okay=False,
        readable=True,
        help="Folder containing scanner JSON/SARIF report files",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        dir_okay=True,
        file_okay=False,
        prompt="Output folder for consolidated report",
        prompt_required=False,
        help="Output folder where consolidated HTML will be written (defaults to --input when omitted)",
    ),
    target: str = typer.Option("consolidated-scan", "--target", help="Consolidated target label"),
    modified_since: str | None = typer.Option(
        None,
        "--modified-since",
        help="Only include files modified on or after this time. Accepts ISO date/datetime or: today, yesterday, last-week, last-7-days",
    ),
    modified_until: str | None = typer.Option(
        None,
        "--modified-until",
        help="Only include files modified on or before this time. Accepts ISO date/datetime, today, or yesterday. Combine with --modified-since for a date range.",
    ),
    limit: int | None = typer.Option(
        None,
        "--limit",
        min=1,
        help="Maximum number of most recently modified report files to include after filtering",
    ),
) -> None:
    """Render a consolidated HTML report from all supported report files in a directory."""
    if output is None:
        output = input

    candidates = _collect_consolidated_candidates(
        input_dir=input,
        modified_since=modified_since,
        modified_until=modified_until,
        limit=limit,
    )

    all_findings = []
    findings_by_parser: dict[str, list[Any]] = {}
    included_sources: set[str] = set()
    included_files = 0
    skipped_files = 0
    for report_file in candidates:
        try:
            payload = _load_json(report_file)
            parser = detect_source_type(payload)
            findings = _parse_findings(payload, parser)
            all_findings.extend(findings)
            findings_by_parser.setdefault(parser, []).extend(findings)
            included_sources.add(parser)
            included_files += 1
            typer.echo(f"[INFO] Included {report_file.name} as {parser} ({len(findings)} findings)")
        except Exception as exc:  # pragma: no cover
            skipped_files += 1
            typer.echo(f"[WARN] Skipping {report_file.name}: {exc}")

    output.mkdir(parents=True, exist_ok=True)
    _write_consolidated_tool_reports(output, target, findings_by_parser)

    all_findings = sort_findings(all_findings)
    counts = count_by_severity(all_findings)
    since_dt = _parse_modified_since(modified_since) if modified_since else None
    until_dt = _parse_modified_until(modified_until) if modified_until else None
    report_html = render_consolidated_dashboard_report(
        target_ref=target,
        findings=all_findings,
        counts=counts,
        reports_dir=input,
        output_dir=output,
        modified_since=since_dt,
        modified_until=until_dt,
        included_sources=included_sources,
    )
    output_file = output / "consolidated-security-report.html"
    output_file.write_text(report_html, encoding="utf-8")

    typer.echo(f"[OK] Report generated: {output_file}")
    typer.echo(f"[INFO] Input directory: {input}")
    if modified_since:
        typer.echo(f"[INFO] Modified since filter: {modified_since}")
    if modified_until:
        typer.echo(f"[INFO] Modified until filter: {modified_until}")
    if limit is not None:
        typer.echo(f"[INFO] File limit: {limit}")
    typer.echo(f"[INFO] Files included: {included_files}")
    typer.echo(f"[INFO] Files skipped: {skipped_files}")
    typer.echo(f"[INFO] Total findings: {len(all_findings)}")
    typer.echo(f"[INFO] Severity counts: {counts}")


@mcp_app.command("serve")
def serve_mcp(
    transport: str = typer.Option("stdio", "--transport", help="MCP transport (currently stdio)")
) -> None:
    """Run the MCP server."""
    from sec_report_kit.mcp.server import run_server

    run_server(transport=transport)


ASCII_BANNER = """
 ____  _____ ____   ____  _____ ____   ___  ____ _____   _  _____ _____ 
/ ___|| ____/ ___| |  _ \\| ____|  _ \\ / _ \\|  _ \\_   _| | |/ /_ _|_   _|
\\___ \\|  _|| |     | |_) |  _| | |_) | | | | |_) || |   | ' / | |  | |  
 ___) | |__| |___  |  _ <| |___|  __/| |_| |  _ < | |   | . \\ | |  | |  
|____/|_____|\\____| |_| \\_\\_____|_|    \\___/|_| \\_\\|_|   |_|\\_\\___| |_| 
"""


def main() -> None:
    typer.echo(ASCII_BANNER)
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
