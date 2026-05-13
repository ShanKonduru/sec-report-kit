# Changelog

All notable changes to this project are documented in this file.

## 0.2.3 - 2026-05-13

### Added
- Safety CLI parser support and HTML rendering flow.
- New CLI command: `srk render safety`.
- MCP support for `source_type="safety"`.
- Helper scripts for Safety scan and render:
  - `scripts/run_safety.sh`
  - `scripts/run_safety.bat`
  - `scripts/render_safety_html.sh`
  - `scripts/render_safety_html.bat`
- Offline Safety DB download helpers:
  - `scripts/download_safety_db.py`
  - `scripts/download_safety_db.sh`
  - `scripts/download_safety_db.bat`

### Changed
- Auto-detection now recognizes Safety JSON payloads.
- Tool installation scripts now install Safety CLI in the app venv.
- README updated with Safety usage and offline/local DB workflow guidance.

### Fixed
- Safety run scripts now avoid false success when network failures occur.
- JSON output validation improved for Safety execution paths.
