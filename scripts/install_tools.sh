#!/usr/bin/env bash
set -euo pipefail

# Install this project and pip-audit in the active Python environment.
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install pip-audit

echo "Installed sec-report-kit (editable) and pip-audit."
