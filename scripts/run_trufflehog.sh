#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-security_reports}"
TARGET_PATH="${2:-.}"
OUT_JSON="${REPORT_DIR}/trufflehog.json"

mkdir -p "${REPORT_DIR}"

if ! command -v trufflehog >/dev/null 2>&1; then
  echo "trufflehog is not installed or not on PATH."
  echo "Install from: https://github.com/trufflesecurity/trufflehog"
  exit 1
fi

# TruffleHog writes one JSON object per line.
trufflehog filesystem "${TARGET_PATH}" --json > "${OUT_JSON}"

echo "TruffleHog JSON report written to ${OUT_JSON}"
