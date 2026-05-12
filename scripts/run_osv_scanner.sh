#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-security_reports}"
TARGET_PATH="${2:-.}"
OUT_JSON="${REPORT_DIR}/osv-scanner.json"

mkdir -p "${REPORT_DIR}"

if ! command -v osv-scanner >/dev/null 2>&1; then
  echo "osv-scanner is not installed or not on PATH."
  echo "Install from: https://github.com/google/osv-scanner"
  exit 1
fi

osv-scanner scan --recursive "${TARGET_PATH}" --format json --output "${OUT_JSON}"

echo "OSV-Scanner JSON report written to ${OUT_JSON}"
