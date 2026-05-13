#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python}"
if [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
  PYTHON_BIN="$(dirname "$0")/../.venv/bin/python"
fi

OUTPUT_DIR="${1:-.tools/safety-db}"
shift || true

# Pass remaining flags (e.g. --full, --no-verify-ssl) directly to the Python script
"${PYTHON_BIN}" "$(dirname "$0")/download_safety_db.py" --output-dir "${OUTPUT_DIR}" "$@"
