# sec-report-kit

Generate HTML vulnerability reports from multiple security tools (SAST, SCA, IaC, and secrets) with a CLI and MCP server.

Supported source types:

- `trivy`
- `pip-audit`
- `bandit`
- `gitleaks`
- `semgrep`
- `codeql` (SARIF)
- `osv-scanner`
- `checkov`
- `tfsec`
- `trufflehog` (JSON or NDJSON)

## Install

```bash
pip install -e .
```

With MCP support:

```bash
pip install -e .[mcp]
```

## CLI Usage

Both commands are available:

- `srk`
- `sec-report-kit`

Render Trivy JSON:

```bash
srk render trivy --input security_reports/trivy-image-report-v1.0.21.json --output security_reports/report-trivy.html --target shankonduru/cpkc-poc:v1.0.21
```

Render pip-audit JSON:

```bash
srk render pip-audit --input pip-audit.json --output security_reports/report-pip-audit.html --target requirements.txt
```

## Helper Scripts (bat/sh)

Cross-platform helper scripts are available in `scripts/`.

Install this package and Python-installable scanners:

```bash
# Linux/macOS
bash scripts/install_tools.sh

# Windows
scripts\install_tools.bat
```

After cloning on a new machine, run the install script above to recreate the local `.tools/` directory and download required binaries. The `.tools/` folder is intentionally not committed to git.

Run all unit tests locally with coverage:

```bash
# Linux/macOS (optional arg: <coverage_dir>)
bash scripts/run_unit_tests_with_coverage.sh
bash scripts/run_unit_tests_with_coverage.sh htmlcov

# Windows (optional arg: <coverage_dir>)
scripts\run_unit_tests_with_coverage.bat
scripts\run_unit_tests_with_coverage.bat htmlcov
```

Run pip-audit and write JSON output:

```bash
# Linux/macOS (optional args: <report_dir> <requirements_file>)
bash scripts/run_pip_audit.sh
bash scripts/run_pip_audit.sh reports requirements.txt

# Windows (optional args: <report_dir> <requirements_file>)
scripts\run_pip_audit.bat
scripts\run_pip_audit.bat reports requirements.txt
```

Convert pip-audit JSON report to HTML:

```bash
# Linux/macOS (optional args: <report_dir> <target_name>)
bash scripts/render_pip_audit_html.sh
bash scripts/render_pip_audit_html.sh reports requirements.txt

# Windows (optional args: <report_dir> <target_name>)
scripts\render_pip_audit_html.bat
scripts\render_pip_audit_html.bat reports requirements.txt
```

These render helpers generate the HTML file and open it automatically in your default browser.

Convert sample Trivy JSON report to HTML:

```bash
# Linux/macOS (optional args: <report_dir> <target_name>)
bash scripts/render_trivy_html.sh
bash scripts/render_trivy_html.sh security_reports my-image

# Windows (optional args: <report_dir> <target_name>)
scripts\render_trivy_html.bat
scripts\render_trivy_html.bat security_reports my-image
```

Convert sample Bandit JSON report to HTML:

```bash
# Linux/macOS (optional args: <report_dir> <target_name>)
bash scripts/render_bandit_html.sh
bash scripts/render_bandit_html.sh security_reports my-python-project

# Windows (optional args: <report_dir> <target_name>)
scripts\render_bandit_html.bat
scripts\render_bandit_html.bat security_reports my-python-project
```

Convert sample Gitleaks JSON report to HTML:

```bash
# Linux/macOS (optional args: <report_dir> <target_name>)
bash scripts/render_gitleaks_html.sh
bash scripts/render_gitleaks_html.sh security_reports my-repository

# Windows (optional args: <report_dir> <target_name>)
scripts\render_gitleaks_html.bat
scripts\render_gitleaks_html.bat security_reports my-repository
```

By default, JSON is written to `reports/pip-audit.json` and HTML to `reports/pip-audit-report.html`.

## Additional Tool Workflows

Each workflow has paired run and render scripts in `scripts/`:

- Semgrep: `run_semgrep.(sh|bat)` and `render_semgrep_html.(sh|bat)`
- CodeQL: `run_codeql.(sh|bat)` and `render_codeql_html.(sh|bat)`
- OSV-Scanner: `run_osv_scanner.(sh|bat)` and `render_osv_scanner_html.(sh|bat)`
- Checkov: `run_checkov.(sh|bat)` and `render_checkov_html.(sh|bat)`
- tfsec: `run_tfsec.(sh|bat)` and `render_tfsec_html.(sh|bat)`
- TruffleHog: `run_trufflehog.(sh|bat)` and `render_trufflehog_html.(sh|bat)`

Manual CLI render examples:

```bash
srk render semgrep --input security_reports/semgrep.json --output security_reports/semgrep-report.html --target my-repo
srk render codeql --input security_reports/codeql.sarif.json --output security_reports/codeql-report.html --target my-repo
srk render osv-scanner --input security_reports/osv-scanner.json --output security_reports/osv-scanner-report.html --target requirements.txt
srk render checkov --input security_reports/checkov.json --output security_reports/checkov-report.html --target terraform
srk render tfsec --input security_reports/tfsec.json --output security_reports/tfsec-report.html --target terraform
srk render trufflehog --input security_reports/trufflehog.json --output security_reports/trufflehog-report.html --target my-repo
```

Render Bandit JSON:

```bash
srk render bandit --input bandit-report.json --output security_reports/report-bandit.html --target my-python-project
```

Render Gitleaks JSON:

```bash
srk render gitleaks --input gitleaks-report.json --output security_reports/report-gitleaks.html --target my-repository
```
## MCP Server

Run MCP server over stdio:

```bash
srk mcp serve --transport stdio
```

### Available MCP Tools

| Tool | Description |
|---|---|
| `summarize_json` | Summarize vulnerabilities by severity from a JSON file |
| `render_report_from_json` | Parse JSON and render an HTML report to disk |
| `validate_input` | Validate that a JSON file is parseable and return finding count |

All tools accept `source_type` (`"trivy"`, `"pip-audit"`, `"bandit"`, `"gitleaks"`, `"semgrep"`, `"codeql"`, `"osv-scanner"`, `"checkov"`, `"tfsec"`, `"trufflehog"`, or `"auto"`) and `input_path` (absolute path to JSON file).

---

### VS Code (GitHub Copilot Agent / MCP extension)

Add to your VS Code `settings.json` (or `.vscode/mcp.json` in the workspace):

```json
{
  "mcp": {
    "servers": {
      "sec-report-kit": {
        "type": "stdio",
        "command": "srk",
        "args": ["mcp", "serve", "--transport", "stdio"]
      }
    }
  }
}
```

> **Note:** If `srk` is not on the system PATH, replace `"command"` with the full path to the executable, e.g. `"C:/Users/you/.venv/Scripts/srk.exe"`.

---

### Claude Desktop

Edit `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "sec-report-kit": {
      "command": "srk",
      "args": ["mcp", "serve", "--transport", "stdio"]
    }
  }
}
```

---

### Cursor

Open **Cursor Settings → MCP** and add a new server entry:

```json
{
  "sec-report-kit": {
    "command": "srk",
    "args": ["mcp", "serve", "--transport", "stdio"]
  }
}
```

Or add it to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "sec-report-kit": {
      "command": "srk",
      "args": ["mcp", "serve", "--transport", "stdio"]
    }
  }
}
```

---

### Windsurf (Codeium)

Edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "sec-report-kit": {
      "command": "srk",
      "args": ["mcp", "serve", "--transport", "stdio"]
    }
  }
}
```

---

### Using a virtual environment

If the package is installed in a `.venv`, use the full path to avoid PATH issues:

**Windows:**
```json
{
  "command": "C:/MyProjects/sec-report-kit/.venv/Scripts/srk.exe",
  "args": ["mcp", "serve", "--transport", "stdio"]
}
```

**macOS / Linux:**
```json
{
  "command": "/home/user/sec-report-kit/.venv/bin/srk",
  "args": ["mcp", "serve", "--transport", "stdio"]
}
```

## Package Publish

Build:

```bash
python -m build
```

Upload to TestPyPI:

```bash
python -m twine upload --repository testpypi dist/*
```

Upload to PyPI:

```bash
python -m twine upload dist/*
```
