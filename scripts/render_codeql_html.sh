#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python}"
if [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
  PYTHON_BIN="$(dirname "$0")/../.venv/bin/python"
fi

REPORT_DIR="${1:-security_reports}"
TARGET_NAME="${2:-repository}"
IN_JSON="${REPORT_DIR}/codeql.sarif.json"
OUT_HTML="${REPORT_DIR}/codeql-report.html"

open_html() {
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$1" >/dev/null 2>&1 &
    return 0
  fi
  if command -v open >/dev/null 2>&1; then
    open "$1" >/dev/null 2>&1 &
    return 0
  fi
  echo "HTML generated but no supported browser opener was found. Open manually: $1"
}

if [[ ! -f "${IN_JSON}" ]]; then
  echo "Missing input JSON: ${IN_JSON}"
  echo "Run scripts/run_codeql.sh first."
  exit 1
fi

"${PYTHON_BIN}" -m sec_report_kit render codeql --input "${IN_JSON}" --output "${OUT_HTML}" --target "${TARGET_NAME}"

echo "HTML report written to ${OUT_HTML}"
open_html "${OUT_HTML}"
