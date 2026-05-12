@echo off
setlocal

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_PATH=%~2"
if "%TARGET_PATH%"=="" set "TARGET_PATH=."

set "OUT_JSON=%REPORT_DIR%\osv-scanner.json"
set "OSV_CMD=osv-scanner"

if exist "%~dp0..\.tools\bin\osv-scanner.exe" set "OSV_CMD=%~dp0..\.tools\bin\osv-scanner.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

where "%OSV_CMD%" >nul 2>&1
if errorlevel 1 if /I "%OSV_CMD%"=="osv-scanner" (
  echo osv-scanner is not installed or not on PATH.
  echo Install from: https://github.com/google/osv-scanner
  exit /b 1
)

"%OSV_CMD%" scan --recursive "%TARGET_PATH%" --format json --output "%OUT_JSON%"
if errorlevel 1 exit /b 1

echo OSV-Scanner JSON report written to %OUT_JSON%
