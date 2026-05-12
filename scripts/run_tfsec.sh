#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-security_reports}"
TARGET_PATH="${2:-.}"
OUT_JSON="${REPORT_DIR}/tfsec.json"

mkdir -p "${REPORT_DIR}"

if ! command -v tfsec >/dev/null 2>&1; then
  echo "tfsec is not installed or not on PATH."
  echo "Install from: https://github.com/aquasecurity/tfsec"
  exit 1
fi

set +e
tfsec "${TARGET_PATH}" --format json --out "${OUT_JSON}"
TFSEC_EXIT=$?
set -e

if [[ ${TFSEC_EXIT} -gt 1 ]]; then
  echo "tfsec failed with exit code ${TFSEC_EXIT}"
  exit ${TFSEC_EXIT}
fi

echo "tfsec JSON report written to ${OUT_JSON}"
