@echo off
setlocal

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_PATH=%~2"
if "%TARGET_PATH%"=="" set "TARGET_PATH=."

set "OUT_JSON=%REPORT_DIR%\bandit.json"
set "BANDIT_PYTHON=python"
if exist "%~dp0..\.venv\Scripts\python.exe" set "BANDIT_PYTHON=%~dp0..\.venv\Scripts\python.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

"%BANDIT_PYTHON%" -c "import bandit" >nul 2>&1
if errorlevel 1 (
  echo bandit is not installed in the configured Python environment.
  echo Install with scripts\install_tools.bat ^(preferred^) or pip install bandit
  exit /b 1
)

"%BANDIT_PYTHON%" -m bandit -r "%TARGET_PATH%" -f json -o "%OUT_JSON%"
set "BANDIT_EXIT=%ERRORLEVEL%"
if %BANDIT_EXIT% GTR 1 (
  echo bandit failed with exit code %BANDIT_EXIT%
  exit /b %BANDIT_EXIT%
)

if %BANDIT_EXIT% EQU 1 (
  echo bandit found issues ^(exit code 1^). JSON report was still generated.
)

echo Bandit JSON report written to %OUT_JSON%
