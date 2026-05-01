@echo off
setlocal

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=reports"

set "TARGET_NAME=%~2"
if "%TARGET_NAME%"=="" set "TARGET_NAME=python-environment"

set "IN_JSON=%REPORT_DIR%\pip-audit.json"
set "OUT_HTML=%REPORT_DIR%\pip-audit-report.html"

if not exist "%IN_JSON%" (
  echo Missing input JSON: %IN_JSON%
  echo Run scripts\run_pip_audit.bat first.
  exit /b 1
)

python -m sec_report_kit render pip-audit --input "%IN_JSON%" --output "%OUT_HTML%" --target "%TARGET_NAME%"
if errorlevel 1 exit /b 1

echo HTML report written to %OUT_HTML%
