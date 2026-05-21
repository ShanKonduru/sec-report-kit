#!/usr/bin/env bash
set -euo pipefail

PROFILE="${1:-shan_s_mcp_hub}"
TARGET_PATH="${2:-$(dirname "$0")/..}"

if command -v cygpath >/dev/null 2>&1; then
  # Git Bash/MSYS path -> Windows path for Docker Desktop on Windows.
  ABS_PATH="$(cygpath -w "$(cd "$TARGET_PATH" && pwd)")"
else
  ABS_PATH="$(cd "$TARGET_PATH" && pwd)"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker CLI was not found in PATH."
  exit 1
fi

echo "Using profile: ${PROFILE}"
echo "Allowing path: ${ABS_PATH}"

SERVER_REF="catalog://mcp/docker-mcp-catalog/filesystem"
if docker mcp profile server add "${PROFILE}" --server "${SERVER_REF}" >/dev/null 2>&1; then
  echo "Added filesystem server to profile."
else
  echo "Filesystem server may already exist in profile. Continuing..."
fi

ESCAPED_PATH="${ABS_PATH//\\/\\\\}"
docker mcp profile config "${PROFILE}" --set "filesystem.paths=[${ESCAPED_PATH}]"

echo
echo "Done. Current filesystem.paths value:"
docker mcp profile config "${PROFILE}" --get filesystem.paths

echo
echo "Example:"
echo "  ./scripts/mcp_add_workspace_filesystem.sh shan_s_mcp_hub /c/MyProjects/sec-report-kit"
