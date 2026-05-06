#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python}"
if [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
	PYTHON_BIN="$(dirname "$0")/../.venv/bin/python"
fi

# Install this project, test tools, and pip-audit in the active Python environment.
"${PYTHON_BIN}" -m pip install --upgrade pip
"${PYTHON_BIN}" -m pip install -e .[dev]
"${PYTHON_BIN}" -m pip install pip-audit

echo "Installed sec-report-kit (editable), dev tools, and pip-audit."
