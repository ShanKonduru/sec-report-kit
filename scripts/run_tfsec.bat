@echo off
setlocal

set "REPO_ROOT=%~dp0.."
set "APP_PYTHON=python"
if exist "%REPO_ROOT%\.venv\Scripts\python.exe" set "APP_PYTHON=%REPO_ROOT%\.venv\Scripts\python.exe"

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_PATH=%~2"
if "%TARGET_PATH%"=="" set "TARGET_PATH=."

set "OUT_JSON=%REPORT_DIR%\tfsec.json"
set "TFSEC_CMD=tfsec"

if exist "%~dp0..\.tools\bin\tfsec.exe" set "TFSEC_CMD=%~dp0..\.tools\bin\tfsec.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

where "%TFSEC_CMD%" >nul 2>&1
if errorlevel 1 if /I "%TFSEC_CMD%"=="tfsec" (
  echo tfsec not found. Attempting local install into .tools\bin...
  "%APP_PYTHON%" "%~dp0install_external_clis.py" --repo-root "%REPO_ROOT%"
  if exist "%~dp0..\.tools\bin\tfsec.exe" set "TFSEC_CMD=%~dp0..\.tools\bin\tfsec.exe"
  where "%TFSEC_CMD%" >nul 2>&1
  if errorlevel 1 if /I "%TFSEC_CMD%"=="tfsec" (
    echo tfsec is not installed or not on PATH.
    echo Install from: https://github.com/aquasecurity/tfsec
    exit /b 1
  )
)

"%TFSEC_CMD%" "%TARGET_PATH%" --format json --out "%OUT_JSON%"
set "TFSEC_EXIT=%ERRORLEVEL%"
if %TFSEC_EXIT% GTR 1 (
  echo tfsec failed with exit code %TFSEC_EXIT%
  exit /b %TFSEC_EXIT%
)

echo tfsec JSON report written to %OUT_JSON%
