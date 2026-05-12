#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python}"
if [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
  PYTHON_BIN="$(dirname "$0")/../.venv/bin/python"
fi

REPORT_DIR="${1:-security_reports}"
TARGET_NAME="${2:-repository}"
IN_JSON="${REPORT_DIR}/trufflehog.json"
OUT_HTML="${REPORT_DIR}/trufflehog-report.html"

if [[ ! -f "${IN_JSON}" ]]; then
  echo "Missing input JSON: ${IN_JSON}"
  echo "Run scripts/run_trufflehog.sh first."
  exit 1
fi

"${PYTHON_BIN}" -m sec_report_kit render trufflehog --input "${IN_JSON}" --output "${OUT_HTML}" --target "${TARGET_NAME}"

echo "HTML report written to ${OUT_HTML}"
