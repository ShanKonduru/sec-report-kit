from __future__ import annotations

import datetime as dt
import html

from sec_report_kit.models import Finding


def _esc(value: str) -> str:
    return html.escape(value, quote=True)


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
