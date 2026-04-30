from __future__ import annotations

import json
from pathlib import Path

from sec_report_kit.parsers import detect_source_type
from sec_report_kit.parsers.pip_audit import parse_pip_audit_json
from sec_report_kit.parsers.trivy import parse_trivy_json
from sec_report_kit.report.html_renderer import render_html_report
from sec_report_kit.services.summarize import count_by_severity, sort_findings


def _load_payload(source_type: str, input_path: str):
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    if source_type == "auto":
        source_type = detect_source_type(data)
    if source_type == "trivy":
        return sort_findings(parse_trivy_json(data))
    if source_type == "pip-audit":
        return sort_findings(parse_pip_audit_json(data))
    raise ValueError("source_type must be 'trivy', 'pip-audit', or 'auto'")


def build_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "MCP dependencies are not installed. Install with: pip install sec-report-kit[mcp]"
        ) from exc

    mcp = FastMCP("sec-report-kit")

    @mcp.tool()
    def summarize_json(source_type: str, input_path: str) -> dict:
        findings = _load_payload(source_type=source_type, input_path=input_path)
        counts = count_by_severity(findings)
        return {"total": len(findings), "counts": counts}

    @mcp.tool()
    def render_report_from_json(source_type: str, input_path: str, output_path: str, target: str) -> dict:
        findings = _load_payload(source_type=source_type, input_path=input_path)
        counts = count_by_severity(findings)
        html = render_html_report(target_ref=target, source_label=source_type, findings=findings, counts=counts)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")
        return {"output_path": str(out), "total": len(findings), "counts": counts}

    @mcp.tool()
    def validate_input(source_type: str, input_path: str) -> dict:
        findings = _load_payload(source_type=source_type, input_path=input_path)
        return {"valid": True, "total_findings": len(findings)}

    return mcp


def run_server(transport: str = "stdio") -> None:
    mcp = build_server()
    if transport != "stdio":
        raise ValueError("Only stdio transport is currently supported")
    mcp.run(transport="stdio")
