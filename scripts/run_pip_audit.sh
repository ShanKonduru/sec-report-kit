#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-reports}"
REQ_FILE="${2:-}"
OUT_JSON="${REPORT_DIR}/pip-audit.json"

mkdir -p "${REPORT_DIR}"

set +e
if [[ -n "${REQ_FILE}" ]]; then
  python -m pip_audit -r "${REQ_FILE}" -f json -o "${OUT_JSON}" --progress-spinner off
  AUDIT_EXIT=$?
else
  python -m pip_audit -f json -o "${OUT_JSON}" --progress-spinner off
  AUDIT_EXIT=$?
fi
set -e

# pip-audit uses exit code 1 when vulnerabilities are found.
if [[ ${AUDIT_EXIT} -gt 1 ]]; then
  echo "pip-audit failed with exit code ${AUDIT_EXIT}"
  exit ${AUDIT_EXIT}
fi

if [[ ${AUDIT_EXIT} -eq 1 ]]; then
  echo "pip-audit found vulnerabilities (exit code 1). JSON report was still generated."
fi

echo "pip-audit JSON report written to ${OUT_JSON}"
