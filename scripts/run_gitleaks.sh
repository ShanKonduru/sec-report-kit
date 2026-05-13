#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-security_reports}"
TARGET_PATH="${2:-.}"
OUT_JSON="${REPORT_DIR}/gitleaks.json"
GITLEAKS_CMD="gitleaks"

if [[ -x "$(dirname "$0")/../.tools/bin/gitleaks" ]]; then
  GITLEAKS_CMD="$(dirname "$0")/../.tools/bin/gitleaks"
fi

mkdir -p "${REPORT_DIR}"

if ! command -v "${GITLEAKS_CMD}" >/dev/null 2>&1; then
  echo "gitleaks is not installed or not on PATH."
  echo "Install from: https://github.com/gitleaks/gitleaks"
  exit 1
fi

set +e
"${GITLEAKS_CMD}" detect --source "${TARGET_PATH}" --report-format json --report-path "${OUT_JSON}"
GITLEAKS_EXIT=$?
set -e

if [[ ${GITLEAKS_EXIT} -gt 1 ]]; then
  echo "gitleaks failed with exit code ${GITLEAKS_EXIT}"
  exit ${GITLEAKS_EXIT}
fi

if [[ ${GITLEAKS_EXIT} -eq 1 ]]; then
  echo "gitleaks found leaks (exit code 1). JSON report was still generated."
fi

echo "Gitleaks JSON report written to ${OUT_JSON}"
