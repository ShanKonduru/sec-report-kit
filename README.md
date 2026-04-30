# sec-report-kit

Generate HTML vulnerability reports from Trivy and pip-audit JSON with a CLI and MCP server.

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

All tools accept `source_type` (`"trivy"` or `"pip-audit"`) and `input_path` (absolute path to JSON file).

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
