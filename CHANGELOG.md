# Changelog

All notable changes to this project are documented in this file.

## 0.2.8 - 2026-05-17

### Changed
- Consolidated report helpers now force the workspace `src/` directory onto `PYTHONPATH` so the generated HTML uses the current source tree.

### Fixed
- The consolidated dashboard footer now shows the requested `sec-report-kit` repository link and developer LinkedIn link.

## 0.2.7 - 2026-05-17

### Added
- Test coverage now includes the consolidated date-filter helpers, Safety parser fallback branches, and consolidated HTML dashboard visibility paths, bringing enforced suite coverage to 100%.

### Fixed
- `requirements.txt` now pins `urllib3==2.7.0` to resolve the Trivy-reported CVEs affecting `2.6.3`.

## 0.2.6 - 2026-05-17

### Added
- Consolidated report rendering now supports bounded file pickup with `--modified-until`, enabling date-range selection when combined with `--modified-since`.

### Changed
- README examples now document both date-range filtering and "from date until today" usage for consolidated report generation.

### Fixed
- `scripts/render_consolidated_html.bat` no longer forwards the first two positional arguments as unexpected extras on Windows.

## 0.2.5 - 2026-05-17

### Added
- New CLI command: `srk render consolidated` to build a single HTML report from all supported scanner reports in an input folder.
- New helper scripts for consolidated rendering:
  - `scripts/render_consolidated_html.sh`
  - `scripts/render_consolidated_html.bat`

### Changed
- `src/sec_report_kit/generate_consolidated_security_report.py` now acts as a wrapper that accepts `--input`, `--output`, and `--target`, and delegates to the consolidated CLI renderer.

### Fixed
- Unified package version metadata by aligning `src/sec_report_kit/__init__.py` with the project version.

## 0.2.4 - 2026-05-14

### Added
- `scripts/install_external_clis.py` now supports `--tool` for targeted installs.
- `scripts/install_external_clis.py` now supports `--force` to re-download tools even when already installed.
- `README.md` now documents external CLI installer options and usage examples.

### Changed
- External CLI installer now skips already-installed tools by default.
- CodeQL install handling on Windows now uses staged extraction and merge to avoid directory lock errors during reinstall.
- `scripts/run_osv_scanner.bat` now auto-generates `requirements.txt` from installed packages when no supported lockfile is present.

### Fixed
- `scripts/run_codeql.bat` now repairs incomplete local CodeQL installs and validates SARIF output existence.
- `scripts/run_codeql.sh` now validates SARIF output existence after analysis.
- `scripts/run_trufflehog.bat` now writes scanner output via temp files to avoid self-scan file locking.
- `scripts/run_trufflehog.bat` now writes `[]` when no findings are present.

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
