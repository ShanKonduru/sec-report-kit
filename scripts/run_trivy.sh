#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-security_reports}"
TARGET_IMAGE="${2:-alpine:latest}"
OUT_JSON="${REPORT_DIR}/trivy-image-report-v1.0.21.json"
TRIVY_CMD="trivy"

if [[ -x "$(dirname "$0")/../.tools/bin/trivy" ]]; then
  TRIVY_CMD="$(dirname "$0")/../.tools/bin/trivy"
fi

mkdir -p "${REPORT_DIR}"

if ! command -v "${TRIVY_CMD}" >/dev/null 2>&1; then
  echo "trivy is not installed or not on PATH."
  echo "Install from: https://github.com/aquasecurity/trivy"
  exit 1
fi

"${TRIVY_CMD}" image --format json --output "${OUT_JSON}" "${TARGET_IMAGE}"

echo "Trivy JSON report written to ${OUT_JSON}"
