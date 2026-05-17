from __future__ import annotations

import datetime as dt
import html
import os
from pathlib import Path

from sec_report_kit.models import Finding


def _esc(value: str) -> str:
    return html.escape(value, quote=True)


def _normalize_tool_key(value: str) -> str:
  return value.strip().lower().replace("_", "-")


def _count_severities(findings: list[Finding]) -> dict[str, int]:
  counted = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
  for item in findings:
    sev = item.severity.upper()
    counted[sev if sev in counted else "UNKNOWN"] += 1
  return counted


def _find_first_existing(base_dirs: list[Path], file_names: list[str]) -> Path | None:
  for file_name in file_names:
    for base in base_dirs:
      candidate = base / file_name
      if candidate.exists() and candidate.is_file():
        return candidate
  return None


def _to_href(from_dir: Path, target_file: Path) -> str:
  relative = Path(os.path.relpath(target_file, from_dir))
  return relative.as_posix()


def render_consolidated_dashboard_report(
  target_ref: str,
  findings: list[Finding],
  counts: dict[str, int],
  reports_dir: Path,
  output_dir: Path,
) -> str:
  generated_at = dt.datetime.now(dt.timezone.utc).isoformat()

  tool_specs = [
    {
      "key": "pip-audit",
      "name": "pip-audit",
      "subtitle": "Dependency Vulnerability Scan",
      "report_files": ["pip-audit-report.html", "pip_audit_report.html"],
      "run_hint": "scripts/render_pip_audit_html",
    },
    {
      "key": "trivy",
      "name": "Trivy",
      "subtitle": "Filesystem and Configuration Audit",
      "report_files": ["trivy-report.html", "trivy_fs_report.html"],
      "run_hint": "scripts/render_trivy_html",
    },
    {
      "key": "gitleaks",
      "name": "GitLeaks",
      "subtitle": "Secret Detection",
      "report_files": ["gitleaks-report.html", "gitleaks_report.html"],
      "run_hint": "scripts/render_gitleaks_html",
    },
    {
      "key": "safety",
      "name": "Safety",
      "subtitle": "Python Dependency Vulnerability Scan",
      "report_files": ["safety-report.html", "safety_report.html"],
      "run_hint": "scripts/render_safety_html",
    },
    {
      "key": "bandit",
      "name": "Bandit",
      "subtitle": "Python Static Security Analysis",
      "report_files": ["bandit-report.html", "bandit_report.html"],
      "run_hint": "scripts/render_bandit_html",
    },
    {
      "key": "semgrep",
      "name": "Semgrep",
      "subtitle": "SAST Rules Scan",
      "report_files": ["semgrep-report.html", "semgrep_report.html"],
      "run_hint": "scripts/render_semgrep_html",
    },
    {
      "key": "codeql",
      "name": "CodeQL",
      "subtitle": "Code Query Analysis",
      "report_files": ["codeql-report.html", "codeql_report.html"],
      "run_hint": "scripts/render_codeql_html",
    },
    {
      "key": "osv-scanner",
      "name": "OSV-Scanner",
      "subtitle": "Open Source Vulnerability Scan",
      "report_files": ["osv-scanner-report.html", "osv_scanner_report.html"],
      "run_hint": "scripts/render_osv_scanner_html",
    },
    {
      "key": "checkov",
      "name": "Checkov",
      "subtitle": "IaC Security Scan",
      "report_files": ["checkov-report.html", "checkov_report.html"],
      "run_hint": "scripts/render_checkov_html",
    },
    {
      "key": "tfsec",
      "name": "tfsec",
      "subtitle": "Terraform Security Scan",
      "report_files": ["tfsec-report.html", "tfsec_report.html"],
      "run_hint": "scripts/render_tfsec_html",
    },
    {
      "key": "trufflehog",
      "name": "TruffleHog",
      "subtitle": "Secrets Discovery",
      "report_files": ["trufflehog-report.html", "trufflehog_report.html"],
      "run_hint": "scripts/render_trufflehog_html",
    },
  ]

  normalized_findings: dict[str, list[Finding]] = {}
  for item in findings:
    normalized_key = _normalize_tool_key(item.source_type)
    normalized_findings.setdefault(normalized_key, []).append(item)

  base_dirs = [reports_dir]
  if output_dir != reports_dir:
    base_dirs.append(output_dir)

  tool_rows: list[dict[str, object]] = []
  for spec in tool_specs:
    matched_file = _find_first_existing(base_dirs, spec["report_files"])
    source_findings = normalized_findings.get(spec["key"], [])
    source_counts = _count_severities(source_findings)
    tool_rows.append(
      {
        "key": spec["key"],
        "name": spec["name"],
        "subtitle": spec["subtitle"],
        "run_hint": spec["run_hint"],
        "available": matched_file is not None,
        "href": _to_href(output_dir, matched_file) if matched_file else "",
        "total": len(source_findings),
        "critical": source_counts["CRITICAL"],
        "high": source_counts["HIGH"],
      }
    )

  visible_tools = [
    row for row in tool_rows if bool(row["available"]) or int(row["total"]) > 0
  ]
  if not visible_tools:
    visible_tools = tool_rows

  reports_available = sum(1 for row in visible_tools if bool(row["available"]))
  reports_total = len(visible_tools)

  nav_links = "".join(
    f'<a href="#{_esc(str(row["key"]))}">{_esc(str(row["name"]))} Report</a>' for row in visible_tools
  )

  cards_html = "".join(
    (
      "<article class=\"tool-card\">"
      "<div class=\"tool-head\">"
      f"<h3>{_esc(str(row['name']))}</h3>"
      f"<span class=\"badge {'ok' if row['available'] else 'missing'}\">"
      f"{'Available' if row['available'] else 'Missing'}</span>"
      "</div>"
      f"<p class=\"tool-subtitle\">{_esc(str(row['subtitle']))}</p>"
      "<div class=\"mini-metrics\">"
      f"<div><span>Total</span><strong>{int(row['total'])}</strong></div>"
      f"<div><span>Critical</span><strong>{int(row['critical'])}</strong></div>"
      f"<div><span>High</span><strong>{int(row['high'])}</strong></div>"
      "</div>"
      "</article>"
    )
    for row in visible_tools
  )

  sections_html = ""
  for row in visible_tools:
    if row["available"]:
      sections_html += (
        f'<section id="{_esc(str(row["key"]))}" class="audit-section">'
        "<div class=\"section-header\">"
        "<div>"
        f"<h2>{_esc(str(row['name']))}</h2>"
        f"<p>{_esc(str(row['subtitle']))}</p>"
        "</div>"
        f"<a class=\"open-link\" href=\"{_esc(str(row['href']))}\" target=\"_blank\" rel=\"noopener noreferrer\">Open Full Report</a>"
        "</div>"
        "<div class=\"report-frame\">"
        f"<iframe src=\"{_esc(str(row['href']))}\" title=\"{_esc(str(row['name']))} report\" loading=\"lazy\" referrerpolicy=\"no-referrer\"></iframe>"
        "</div>"
        "</section>"
      )
    else:
      sections_html += (
        f'<section id="{_esc(str(row["key"]))}" class="audit-section">'
        "<div class=\"section-header\">"
        "<div>"
        f"<h2>{_esc(str(row['name']))}</h2>"
        f"<p>{_esc(str(row['subtitle']))}</p>"
        "</div>"
        "</div>"
        "<div class=\"report-frame\">"
        "<div class=\"missing-panel\">"
        "<h4>Tool report not found</h4>"
        f"<p>Generate this report first using {_esc(str(row['run_hint']))}.sh or {_esc(str(row['run_hint']))}.bat.</p>"
        "</div>"
        "</div>"
        "</section>"
      )

  return f"""<!DOCTYPE html>
<html>
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>Security Audit Report - Consolidated</title>
<style>
:root {{
  --bg: #eef3fb;
  --panel: #ffffff;
  --ink: #10213a;
  --muted: #6b7a90;
  --line: #d8e0ee;
  --brand: #1f5fbf;
  --brand-2: #0f3c7a;
  --ok: #157347;
  --warn: #b36a00;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: radial-gradient(circle at top left, #dbe8ff, var(--bg) 55%);
  color: var(--ink);
  font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
}}
.page {{ max-width: 1320px; margin: 0 auto; padding: 22px; }}
.hero {{
  background: linear-gradient(120deg, var(--brand-2), var(--brand));
  color: #fff;
  border-radius: 16px;
  padding: 24px;
  box-shadow: 0 14px 28px rgba(17, 42, 79, 0.25);
}}
.hero h1 {{ margin: 0; font-size: clamp(1.35rem, 2.2vw, 2rem); }}
.hero-meta {{ margin-top: 8px; opacity: 0.9; font-size: 0.95rem; }}
.summary {{
  margin-top: 16px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 10px;
}}
.summary-card {{
  background: rgba(255, 255, 255, 0.16);
  border: 1px solid rgba(255, 255, 255, 0.24);
  border-radius: 10px;
  padding: 10px 12px;
}}
.summary-card .label {{ display: block; font-size: 0.82rem; opacity: 0.92; }}
.summary-card .value {{ display: block; margin-top: 4px; font-size: 1.35rem; font-weight: 700; }}
.layout {{ margin-top: 18px; display: grid; grid-template-columns: 260px 1fr; gap: 16px; }}
.sidebar {{ position: sticky; top: 12px; align-self: start; }}
.panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 14px; box-shadow: 0 8px 18px rgba(11, 28, 54, 0.08); }}
.panel h3 {{ margin: 0 0 10px; font-size: 0.98rem; color: var(--brand-2); }}
.nav-links a {{
  display: block;
  text-decoration: none;
  color: var(--ink);
  font-size: 0.92rem;
  padding: 8px 10px;
  border-radius: 8px;
  margin-bottom: 6px;
  background: #f6f9ff;
  border: 1px solid #e5ecf8;
}}
.nav-links a:hover {{ background: #ebf3ff; border-color: #ceddf5; }}
.tools {{ margin-top: 12px; display: grid; gap: 10px; }}
.tool-card {{ border: 1px solid var(--line); border-radius: 12px; padding: 12px; background: #fff; }}
.tool-head {{ display: flex; align-items: center; justify-content: space-between; gap: 8px; }}
.tool-head h3 {{ margin: 0; font-size: 0.98rem; }}
.badge {{ font-size: 0.75rem; padding: 3px 7px; border-radius: 999px; font-weight: 600; }}
.badge.ok {{ background: #def4e8; color: var(--ok); }}
.badge.missing {{ background: #fff2de; color: var(--warn); }}
.tool-subtitle {{ margin: 7px 0 0; color: var(--muted); font-size: 0.85rem; }}
.mini-metrics {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px; margin-top: 10px; }}
.mini-metrics div {{ background: #f7faff; border: 1px solid #e7eef9; border-radius: 8px; padding: 7px 8px; }}
.mini-metrics span {{ display: block; color: var(--muted); font-size: 0.74rem; }}
.mini-metrics strong {{ display: block; margin-top: 2px; font-size: 0.95rem; }}
.audit-section {{ margin-bottom: 14px; scroll-margin-top: 12px; }}
.section-header {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 8px; }}
.section-header h2 {{ margin: 0; font-size: 1.12rem; }}
.section-header p {{ margin: 2px 0 0; color: var(--muted); font-size: 0.9rem; }}
.open-link {{
  text-decoration: none;
  color: #fff;
  background: var(--brand);
  border: 1px solid #1a53a7;
  border-radius: 8px;
  padding: 7px 11px;
  font-size: 0.84rem;
  white-space: nowrap;
}}
.open-link:hover {{ background: #194f9d; }}
.report-frame {{ border: 1px solid var(--line); border-radius: 12px; overflow: hidden; background: #fff; min-height: 640px; }}
.report-frame iframe {{ width: 100%; height: 680px; border: 0; display: block; }}
.missing-panel {{ padding: 18px; color: var(--muted); }}
.missing-panel h4 {{ margin: 0 0 6px; color: var(--ink); }}
footer {{
  margin-top: 16px;
  text-align: center;
  color: var(--muted);
  font-size: 0.85rem;
  padding: 12px 10px 6px;
}}
@media (max-width: 980px) {{
  .layout {{ grid-template-columns: 1fr; }}
  .sidebar {{ position: static; }}
  .report-frame iframe {{ height: 760px; }}
}}
</style>
</head>
<body>
<main class="page">
  <section class="hero">
  <h1>Security Audit Consolidated Dashboard</h1>
  <div class="hero-meta">Generated: {_esc(generated_at)} | Reports available: {reports_available}/{reports_total} | Target: {_esc(target_ref)}</div>
  <div class="summary">
    <div class="summary-card"><span class="label">Total Findings</span><span class="value">{len(findings)}</span></div>
    <div class="summary-card"><span class="label">Critical</span><span class="value">{counts['CRITICAL']}</span></div>
    <div class="summary-card"><span class="label">High</span><span class="value">{counts['HIGH']}</span></div>
    <div class="summary-card"><span class="label">Medium</span><span class="value">{counts['MEDIUM']}</span></div>
    <div class="summary-card"><span class="label">Low</span><span class="value">{counts['LOW']}</span></div>
    <div class="summary-card"><span class="label">Unknown</span><span class="value">{counts['UNKNOWN']}</span></div>
  </div>
  </section>

  <section class="layout">
  <aside class="sidebar">
    <div class="panel">
    <h3>Quick Navigation</h3>
    <nav class="nav-links">{nav_links}</nav>
    </div>
    <div class="tools">{cards_html}</div>
  </aside>

  <div>{sections_html}</div>
  </section>

  <footer>
  <p>This consolidated dashboard embeds tool-specific HTML reports when available.</p>
  <p>Generate missing tool HTML files using the corresponding scripts in the scripts folder.</p>
  </footer>
</main>
</body>
</html>
"""


def render_html_report(target_ref: str, source_label: str, findings: list[Finding], counts: dict[str, int]) -> str:
    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(findings)

    rows = []
    for item in findings:
        vuln_id = _esc(item.vulnerability_id)
        if item.primary_url:
            vuln_cell = (
                f'<a href="{_esc(item.primary_url)}" target="_blank" rel="noopener noreferrer">{vuln_id}</a>'
            )
        else:
            vuln_cell = vuln_id

        rows.append(
            "<tr>"
            f"<td class=\"sev {_esc(item.severity).lower()}\">{_esc(item.severity)}</td>"
            f"<td>{vuln_cell}</td>"
            f"<td>{_esc(item.package)}</td>"
            f"<td>{_esc(item.installed_version)}</td>"
            f"<td>{_esc(item.fixed_version)}</td>"
            f"<td>{_esc(item.title)}</td>"
            f"<td>{_esc(item.target)}</td>"
            f"<td>{_esc(item.source_type)}</td>"
            "</tr>"
        )

    rows_html = "\n".join(rows) if rows else "<tr><td colspan=\"8\">No vulnerabilities found.</td></tr>"

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Security Report</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; }}
    h1 {{ margin: 0 0 8px 0; }}
    .meta {{ margin-bottom: 18px; color: #4b5563; }}
    .cards {{ display: grid; grid-template-columns: repeat(6, minmax(110px, 1fr)); gap: 10px; margin-bottom: 18px; }}
    .card {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 10px 12px; background: #f9fafb; }}
    .label {{ font-size: 12px; color: #6b7280; text-transform: uppercase; }}
    .value {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
    .filters {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; align-items: center; }}
    .filters label {{ font-size: 13px; color: #374151; display: flex; flex-direction: column; gap: 3px; }}
    .filters select, .filters input[type=text] {{
      font-size: 13px; padding: 5px 8px; border: 1px solid #d1d5db;
      border-radius: 6px; background: #fff; color: #1f2937; min-width: 140px;
    }}
    .filters input[type=text] {{ min-width: 220px; }}
    .filters button {{
      font-size: 13px; padding: 6px 14px; border: 1px solid #d1d5db;
      border-radius: 6px; background: #f3f4f6; cursor: pointer; color: #374151;
      align-self: flex-end;
    }}
    .filters button:hover {{ background: #e5e7eb; }}
    #result-count {{ font-size: 13px; color: #6b7280; align-self: flex-end; margin-left: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    thead th {{ text-align: left; border-bottom: 2px solid #d1d5db; padding: 8px; background: #f3f4f6; position: sticky; top: 0; }}
    tbody td {{ border-bottom: 1px solid #e5e7eb; padding: 8px; vertical-align: top; }}
    tbody tr.hidden {{ display: none; }}
    .sev {{ font-weight: 700; }}
    .critical {{ color: #b91c1c; }}
    .high {{ color: #c2410c; }}
    .medium {{ color: #b45309; }}
    .low {{ color: #1d4ed8; }}
    .unknown {{ color: #6b7280; }}
    a {{ color: #1d4ed8; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .report-footer {{
      margin-top: 36px;
      padding-top: 14px;
      border-top: 1px solid #e5e7eb;
      text-align: center;
      font-size: 12px;
      color: #6b7280;
    }}
  </style>
</head>
<body>
  <h1>Security Vulnerability Report</h1>
  <div class=\"meta\">Source: <strong>{_esc(source_label)}</strong> | Target: <strong>{_esc(target_ref)}</strong> | Generated: {_esc(generated_at)}</div>

  <div class=\"cards\">
    <div class=\"card\"><div class=\"label\">Total</div><div class=\"value\">{total}</div></div>
    <div class=\"card\"><div class=\"label\">Critical</div><div class=\"value critical\">{counts['CRITICAL']}</div></div>
    <div class=\"card\"><div class=\"label\">High</div><div class=\"value high\">{counts['HIGH']}</div></div>
    <div class=\"card\"><div class=\"label\">Medium</div><div class=\"value medium\">{counts['MEDIUM']}</div></div>
    <div class=\"card\"><div class=\"label\">Low</div><div class=\"value low\">{counts['LOW']}</div></div>
    <div class=\"card\"><div class=\"label\">Unknown</div><div class=\"value unknown\">{counts['UNKNOWN']}</div></div>
  </div>

  <div class=\"filters\">
    <label>Severity
      <select id=\"f-severity\">
        <option value=\"\">All</option>
        <option value=\"critical\">Critical</option>
        <option value=\"high\">High</option>
        <option value=\"medium\">Medium</option>
        <option value=\"low\">Low</option>
        <option value=\"unknown\">Unknown</option>
      </select>
    </label>
    <label>Vulnerability ID
      <input type=\"text\" id=\"f-vuln\" placeholder=\"e.g. CVE-2024-\" />
    </label>
    <label>Package
      <input type=\"text\" id=\"f-pkg\" placeholder=\"e.g. openssl\" />
    </label>
    <label>Target
      <input type=\"text\" id=\"f-target\" placeholder=\"e.g. usr/lib\" />
    </label>
    <label>Type
      <input type=\"text\" id=\"f-type\" placeholder=\"e.g. os-pkgs\" />
    </label>
    <label>Title / keyword
      <input type=\"text\" id=\"f-title\" placeholder=\"e.g. buffer overflow\" />
    </label>
    <button onclick=\"clearFilters()\">Clear</button>
    <span id=\"result-count\"></span>
  </div>

  <table id=\"vuln-table\">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Vulnerability</th>
        <th>Package</th>
        <th>Installed</th>
        <th>Fixed</th>
        <th>Title</th>
        <th>Target</th>
        <th>Type</th>
      </tr>
    </thead>
    <tbody id=\"vuln-body\">
      {rows_html}
    </tbody>
  </table>

  <script>
    const filterIds = ['f-severity', 'f-vuln', 'f-pkg', 'f-target', 'f-type', 'f-title'];
    // col indices: severity=0, vuln=1, pkg=2, installed=3, fixed=4, title=5, target=6, type=7
    const colMap = {{ 'f-severity': 0, 'f-vuln': 1, 'f-pkg': 2, 'f-target': 6, 'f-type': 7, 'f-title': 5 }};

    function applyFilters() {{
      const filters = {{}};
      filterIds.forEach(id => {{
        const el = document.getElementById(id);
        filters[id] = el.value.trim().toLowerCase();
      }});

      const rows = document.querySelectorAll('#vuln-body tr');
      let visible = 0;
      rows.forEach(row => {{
        const cells = row.querySelectorAll('td');
        if (!cells.length) return;
        let show = true;
        for (const [id, col] of Object.entries(colMap)) {{
          const val = filters[id];
          if (!val) continue;
          const cellText = (cells[col]?.textContent || '').trim().toLowerCase();
          if (id === 'f-severity') {{
            if (cellText !== val) {{ show = false; break; }}
          }} else {{
            if (!cellText.includes(val)) {{ show = false; break; }}
          }}
        }}
        row.classList.toggle('hidden', !show);
        if (show) visible++;
      }});

      const total = rows.length;
      document.getElementById('result-count').textContent =
        visible === total ? `${{total}} rows` : `${{visible}} of ${{total}} rows`;
    }}

    function clearFilters() {{
      filterIds.forEach(id => {{ document.getElementById(id).value = ''; }});
      applyFilters();
    }}

    filterIds.forEach(id => {{
      const el = document.getElementById(id);
      el.addEventListener('input', applyFilters);
      el.addEventListener('change', applyFilters);
    }});

    applyFilters();
  </script>

  <footer class="report-footer">
    This report is generated by
    <a href="https://github.com/ShanKonduru/sec-report-kit" target="_blank" rel="noopener noreferrer">sec-report-kit</a>
    utility
    &nbsp;|&nbsp;
    Connect with the developer:
    <a href="https://www.linkedin.com/in/shankonduru/" target="_blank" rel="noopener noreferrer">Shan Konduru</a>
  </footer>
</body>
</html>
"""
