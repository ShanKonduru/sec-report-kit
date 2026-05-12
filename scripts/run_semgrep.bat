@echo off
setlocal

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_PATH=%~2"
if "%TARGET_PATH%"=="" set "TARGET_PATH=."

set "OUT_JSON=%REPORT_DIR%\semgrep.json"
set "SEMGREP_CMD=semgrep"

if exist "%~dp0..\.venv-scanners\Scripts\semgrep.exe" set "SEMGREP_CMD=%~dp0..\.venv-scanners\Scripts\semgrep.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

where "%SEMGREP_CMD%" >nul 2>&1
if errorlevel 1 if /I "%SEMGREP_CMD%"=="semgrep" (
  echo semgrep is not installed or not on PATH.
  echo Install with scripts\install_tools.bat ^(preferred^) or pip install semgrep
  exit /b 1
)

"%SEMGREP_CMD%" scan --config auto --json --output "%OUT_JSON%" "%TARGET_PATH%"
if errorlevel 1 exit /b 1

echo Semgrep JSON report written to %OUT_JSON%
