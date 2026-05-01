@echo off
setlocal

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=reports"

set "REQ_FILE=%~2"
set "OUT_JSON=%REPORT_DIR%\pip-audit.json"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

if "%REQ_FILE%"=="" (
  python -m pip_audit -f json -o "%OUT_JSON%" --progress-spinner off
) else (
  python -m pip_audit -r "%REQ_FILE%" -f json -o "%OUT_JSON%" --progress-spinner off
)
set "AUDIT_EXIT=%ERRORLEVEL%"
if %AUDIT_EXIT% GTR 1 (
  echo pip-audit failed with exit code %AUDIT_EXIT%
  exit /b %AUDIT_EXIT%
)

if %AUDIT_EXIT% EQU 1 (
  echo pip-audit found vulnerabilities (exit code 1). JSON report was still generated.
)

echo pip-audit JSON report written to %OUT_JSON%
