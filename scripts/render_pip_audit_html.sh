#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-reports}"
TARGET_NAME="${2:-python-environment}"
IN_JSON="${REPORT_DIR}/pip-audit.json"
OUT_HTML="${REPORT_DIR}/pip-audit-report.html"

if [[ ! -f "${IN_JSON}" ]]; then
  echo "Missing input JSON: ${IN_JSON}"
  echo "Run scripts/run_pip_audit.sh first."
  exit 1
fi

python -m sec_report_kit render pip-audit --input "${IN_JSON}" --output "${OUT_HTML}" --target "${TARGET_NAME}"

echo "HTML report written to ${OUT_HTML}"
