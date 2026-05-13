@echo off
setlocal

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_PATH=%~2"
if "%TARGET_PATH%"=="" set "TARGET_PATH=."

set "OUT_JSON=%REPORT_DIR%\gitleaks.json"
set "GITLEAKS_CMD=gitleaks"

if exist "%~dp0..\.tools\bin\gitleaks.exe" set "GITLEAKS_CMD=%~dp0..\.tools\bin\gitleaks.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

where "%GITLEAKS_CMD%" >nul 2>&1
if errorlevel 1 if /I "%GITLEAKS_CMD%"=="gitleaks" (
  echo gitleaks is not installed or not on PATH.
  echo Install from: https://github.com/gitleaks/gitleaks
  exit /b 1
)

"%GITLEAKS_CMD%" detect --source "%TARGET_PATH%" --report-format json --report-path "%OUT_JSON%"
set "GITLEAKS_EXIT=%ERRORLEVEL%"
if %GITLEAKS_EXIT% GTR 1 (
  echo gitleaks failed with exit code %GITLEAKS_EXIT%
  exit /b %GITLEAKS_EXIT%
)

if %GITLEAKS_EXIT% EQU 1 (
  echo gitleaks found leaks ^(exit code 1^). JSON report was still generated.
)

echo Gitleaks JSON report written to %OUT_JSON%
