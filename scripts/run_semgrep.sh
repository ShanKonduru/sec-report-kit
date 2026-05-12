#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-security_reports}"
TARGET_PATH="${2:-.}"
OUT_JSON="${REPORT_DIR}/semgrep.json"
SEMGREP_CMD="semgrep"

if [[ -x "$(dirname "$0")/../.venv-scanners/bin/semgrep" ]]; then
  SEMGREP_CMD="$(dirname "$0")/../.venv-scanners/bin/semgrep"
fi

mkdir -p "${REPORT_DIR}"

if ! command -v "${SEMGREP_CMD}" >/dev/null 2>&1; then
  echo "semgrep is not installed or not on PATH."
  echo "Install with scripts/install_tools.sh (preferred) or pip install semgrep"
  exit 1
fi

"${SEMGREP_CMD}" scan --config auto --json --output "${OUT_JSON}" "${TARGET_PATH}"

echo "Semgrep JSON report written to ${OUT_JSON}"
