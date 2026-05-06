#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python}"
if [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
	PYTHON_BIN="$(dirname "$0")/../.venv/bin/python"
fi

COV_DIR="${1:-htmlcov}"

echo "Running unit tests with coverage..."
"${PYTHON_BIN}" -m pytest --cov=sec_report_kit --cov-report=term-missing --cov-report=html:"${COV_DIR}" tests

echo "Coverage HTML report written to ${COV_DIR}/index.html"
