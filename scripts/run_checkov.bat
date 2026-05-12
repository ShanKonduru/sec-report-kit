@echo off
setlocal

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_PATH=%~2"
if "%TARGET_PATH%"=="" set "TARGET_PATH=."

set "OUT_JSON=%REPORT_DIR%\checkov.json"
set "CHECKOV_PYTHON="

if exist "%~dp0..\.venv-scanners\Scripts\python.exe" set "CHECKOV_PYTHON=%~dp0..\.venv-scanners\Scripts\python.exe"
if "%CHECKOV_PYTHON%"=="" if exist "%~dp0..\.venv\Scripts\python.exe" set "CHECKOV_PYTHON=%~dp0..\.venv\Scripts\python.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

if "%CHECKOV_PYTHON%"=="" (
  echo No project Python interpreter found.
  exit /b 1
)

"%CHECKOV_PYTHON%" -c "import checkov" >nul 2>&1
if errorlevel 1 (
  echo checkov is not installed in the configured venv.
  echo Install with scripts\install_tools.bat ^(preferred^) or pip install checkov
  exit /b 1
)

"%CHECKOV_PYTHON%" -m checkov.main -d "%TARGET_PATH%" -o json > "%OUT_JSON%"
set "CHECKOV_EXIT=%ERRORLEVEL%"
if %CHECKOV_EXIT% GTR 1 (
  echo checkov failed with exit code %CHECKOV_EXIT%
  exit /b %CHECKOV_EXIT%
)

echo Checkov JSON report written to %OUT_JSON%
