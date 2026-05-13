#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python}"
if [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
  PYTHON_BIN="$(dirname "$0")/../.venv/bin/python"
fi
export PYTHONWARNINGS="ignore"

REPORT_DIR="${1:-security_reports}"
REQ_FILE="${2:-}"
OUT_JSON="${REPORT_DIR}/safety.json"

# Resolve local DB path relative to project root (parent of scripts/)
LOCAL_DB_DIR="$(dirname "$0")/../.tools/safety-db"
LOCAL_DB_FLAG=""
if [[ -f "${LOCAL_DB_DIR}/insecure.json" ]]; then
  LOCAL_DB_FLAG="--db ${LOCAL_DB_DIR}"
  echo "Using local Safety DB at ${LOCAL_DB_DIR}"
else
  echo "No local Safety DB found. Attempting online scan."
  echo "Run scripts/download_safety_db.sh to cache the DB for offline use."
fi

mkdir -p "${REPORT_DIR}"
rm -f "${OUT_JSON}"

set +e
if [[ -n "${REQ_FILE}" ]]; then
  # shellcheck disable=SC2086
  "${PYTHON_BIN}" -W ignore -m safety check --json --file "${REQ_FILE}" ${LOCAL_DB_FLAG} --save-json "${OUT_JSON}" >/dev/null 2>/dev/null
  SAFETY_EXIT=$?
else
  # shellcheck disable=SC2086
  "${PYTHON_BIN}" -W ignore -m safety check --json ${LOCAL_DB_FLAG} --save-json "${OUT_JSON}" >/dev/null 2>/dev/null
  SAFETY_EXIT=$?
fi
set -e

if [[ ! -f "${OUT_JSON}" ]]; then
  if [[ ${SAFETY_EXIT} -eq 68 ]]; then
    echo "Safety CLI could not reach the server (exit code 68) and no JSON report was produced."
    echo "Tip: Run scripts/download_safety_db.sh while online to enable offline scanning."
  else
    echo "Safety CLI failed with exit code ${SAFETY_EXIT} and produced no JSON output."
  fi
  exit ${SAFETY_EXIT}
fi

if ! "${PYTHON_BIN}" -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "${OUT_JSON}" >/dev/null 2>&1; then
  if [[ ${SAFETY_EXIT} -eq 68 ]]; then
    echo "Safety CLI could not reach the server (exit code 68); output file is not valid JSON."
    echo "Tip: Run scripts/download_safety_db.sh while online to enable offline scanning."
  else
    echo "Safety CLI output is not valid JSON (exit code ${SAFETY_EXIT})."
  fi
  exit ${SAFETY_EXIT}
fi

if [[ ${SAFETY_EXIT} -ne 0 ]]; then
  echo "Safety CLI returned exit code ${SAFETY_EXIT}. Valid JSON report was still generated."
fi

echo "Safety JSON report written to ${OUT_JSON}"