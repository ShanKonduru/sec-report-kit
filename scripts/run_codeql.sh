#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-security_reports}"
DATABASE_PATH="${2:-codeql-db}"
QUERY_SUITE="${3:-codeql/python-queries}"
OUT_JSON="${REPORT_DIR}/codeql.sarif.json"
CODEQL_CMD="codeql"

if [[ -x "$(dirname "$0")/../.tools/bin/codeql/codeql" ]]; then
  CODEQL_CMD="$(dirname "$0")/../.tools/bin/codeql/codeql"
fi

mkdir -p "${REPORT_DIR}"

if ! command -v "${CODEQL_CMD}" >/dev/null 2>&1; then
  echo "codeql is not installed or not on PATH."
  echo "Install from: https://codeql.github.com/docs/codeql-overview/codeql-changelog/"
  exit 1
fi

"${CODEQL_CMD}" database analyze "${DATABASE_PATH}" "${QUERY_SUITE}" --format=sarifv2.1.0 --output="${OUT_JSON}"

echo "CodeQL SARIF report written to ${OUT_JSON}"
