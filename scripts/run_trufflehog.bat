@echo off
setlocal

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_PATH=%~2"
if "%TARGET_PATH%"=="" set "TARGET_PATH=."

set "OUT_JSON=%REPORT_DIR%\trufflehog.json"
set "TRUFFLEHOG_CMD=trufflehog"

if exist "%~dp0..\.tools\bin\trufflehog.exe" set "TRUFFLEHOG_CMD=%~dp0..\.tools\bin\trufflehog.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

where "%TRUFFLEHOG_CMD%" >nul 2>&1
if errorlevel 1 if /I "%TRUFFLEHOG_CMD%"=="trufflehog" (
  echo trufflehog is not installed or not on PATH.
  echo Install from: https://github.com/trufflesecurity/trufflehog
  exit /b 1
)

"%TRUFFLEHOG_CMD%" filesystem "%TARGET_PATH%" --json > "%OUT_JSON%"
if errorlevel 1 exit /b 1

echo TruffleHog JSON report written to %OUT_JSON%
