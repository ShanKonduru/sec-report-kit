#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-security_reports}"
TARGET_PATH="${2:-.}"
OUT_JSON="${REPORT_DIR}/checkov.json"
CHECKOV_PYTHON=""

if [[ -x "$(dirname "$0")/../.venv-scanners/bin/python" ]]; then
  CHECKOV_PYTHON="$(dirname "$0")/../.venv-scanners/bin/python"
elif [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
  CHECKOV_PYTHON="$(dirname "$0")/../.venv/bin/python"
fi

mkdir -p "${REPORT_DIR}"

if [[ -z "${CHECKOV_PYTHON}" ]]; then
  echo "No project Python interpreter found."
  exit 1
fi

if ! "${CHECKOV_PYTHON}" -c "import checkov" >/dev/null 2>&1; then
  echo "checkov is not installed in the configured venv."
  echo "Install with scripts/install_tools.sh (preferred) or pip install checkov"
  exit 1
fi

set +e
"${CHECKOV_PYTHON}" -m checkov.main -d "${TARGET_PATH}" -o json > "${OUT_JSON}"
CHECKOV_EXIT=$?
set -e

if [[ ${CHECKOV_EXIT} -gt 1 ]]; then
  echo "checkov failed with exit code ${CHECKOV_EXIT}"
  exit ${CHECKOV_EXIT}
fi

echo "Checkov JSON report written to ${OUT_JSON}"
