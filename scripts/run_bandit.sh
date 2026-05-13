#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-security_reports}"
TARGET_PATH="${2:-.}"
OUT_JSON="${REPORT_DIR}/bandit.json"
BANDIT_PYTHON="${PYTHON_BIN:-python}"

if [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
  BANDIT_PYTHON="$(dirname "$0")/../.venv/bin/python"
fi

mkdir -p "${REPORT_DIR}"

if ! "${BANDIT_PYTHON}" -c "import bandit" >/dev/null 2>&1; then
  echo "bandit is not installed in the configured Python environment."
  echo "Install with scripts/install_tools.sh (preferred) or pip install bandit"
  exit 1
fi

set +e
"${BANDIT_PYTHON}" -m bandit -r "${TARGET_PATH}" -f json -o "${OUT_JSON}"
BANDIT_EXIT=$?
set -e

if [[ ${BANDIT_EXIT} -gt 1 ]]; then
  echo "bandit failed with exit code ${BANDIT_EXIT}"
  exit ${BANDIT_EXIT}
fi

if [[ ${BANDIT_EXIT} -eq 1 ]]; then
  echo "bandit found issues (exit code 1). JSON report was still generated."
fi

echo "Bandit JSON report written to ${OUT_JSON}"
