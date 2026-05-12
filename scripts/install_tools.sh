#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python}"
if [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
	PYTHON_BIN="$(dirname "$0")/../.venv/bin/python"
fi

SCANNER_VENV="$(dirname "$0")/../.venv-scanners"
SCANNER_PYTHON="${SCANNER_VENV}/bin/python"

# Install app and dev dependencies in the primary project venv.
"${PYTHON_BIN}" -m pip install --upgrade pip
"${PYTHON_BIN}" -m pip install -e .[dev]
"${PYTHON_BIN}" -m pip install pip-audit bandit

# Create a dedicated scanner venv to avoid dependency conflicts with app tooling.
if [[ ! -x "${SCANNER_PYTHON}" ]]; then
	echo "Creating scanner venv at ${SCANNER_VENV}"
	"${PYTHON_BIN}" -m venv "${SCANNER_VENV}"
fi

"${SCANNER_PYTHON}" -m pip install --upgrade pip
"${SCANNER_PYTHON}" -m pip install semgrep checkov

echo "Installed in app venv (.venv): sec-report-kit (editable), dev tools, pip-audit, bandit."
echo "Installed in scanner venv (.venv-scanners): semgrep, checkov."
echo "Install external CLIs separately if needed: codeql, tfsec, gitleaks, trufflehog, osv-scanner."
