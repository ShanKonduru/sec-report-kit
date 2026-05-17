#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python}"
if [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
  PYTHON_BIN="$(dirname "$0")/../.venv/bin/python"
fi

REPORT_DIR="${1:-security_reports}"
ROOT_NAME="$(basename "$(cd "$(dirname "$0")/.." && pwd)")"
TARGET_NAME="${2:-${ROOT_NAME}}"
OUT_HTML="${REPORT_DIR}/consolidated-security-report.html"

if [[ $# -gt 0 ]]; then
  shift
fi
if [[ $# -gt 0 ]]; then
  shift
fi

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

if [[ ! -d "${REPORT_DIR}" ]]; then
  echo "Missing input directory: ${REPORT_DIR}"
  exit 1
fi

"${PYTHON_BIN}" -m sec_report_kit render consolidated --input "${REPORT_DIR}" --output "${REPORT_DIR}" --target "${TARGET_NAME}" "$@"

echo "HTML report written to ${OUT_HTML}"
open_html "${OUT_HTML}"
