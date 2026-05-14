@echo off
setlocal

set "REPO_ROOT=%~dp0.."
set "APP_PYTHON=python"
if exist "%REPO_ROOT%\.venv\Scripts\python.exe" set "APP_PYTHON=%REPO_ROOT%\.venv\Scripts\python.exe"

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_PATH=%~2"
if "%TARGET_PATH%"=="" set "TARGET_PATH=."

set "OUT_JSON=%REPORT_DIR%\trufflehog.json"
set "OUT_LOG=%REPORT_DIR%\trufflehog.log"
set "TMP_JSON=%TEMP%\srk-trufflehog-%RANDOM%-%RANDOM%.json"
set "TMP_LOG=%TEMP%\srk-trufflehog-%RANDOM%-%RANDOM%.log"
set "TRUFFLEHOG_CMD=trufflehog"

if exist "%~dp0..\.tools\bin\trufflehog.exe" set "TRUFFLEHOG_CMD=%~dp0..\.tools\bin\trufflehog.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

where "%TRUFFLEHOG_CMD%" >nul 2>&1
if errorlevel 1 if /I "%TRUFFLEHOG_CMD%"=="trufflehog" (
  echo trufflehog not found. Attempting local install into .tools\bin...
  "%APP_PYTHON%" "%~dp0install_external_clis.py" --repo-root "%REPO_ROOT%"
  if exist "%~dp0..\.tools\bin\trufflehog.exe" set "TRUFFLEHOG_CMD=%~dp0..\.tools\bin\trufflehog.exe"
  where "%TRUFFLEHOG_CMD%" >nul 2>&1
  if errorlevel 1 if /I "%TRUFFLEHOG_CMD%"=="trufflehog" (
    echo trufflehog is not installed or not on PATH.
    echo Install from: https://github.com/trufflesecurity/trufflehog
    exit /b 1
  )
)

"%TRUFFLEHOG_CMD%" filesystem "%TARGET_PATH%" --json > "%TMP_JSON%" 2> "%TMP_LOG%"
if errorlevel 1 (
  if exist "%TMP_JSON%" move /Y "%TMP_JSON%" "%OUT_JSON%" >nul
  if exist "%TMP_LOG%" move /Y "%TMP_LOG%" "%OUT_LOG%" >nul
  echo TruffleHog scan failed. See log: %OUT_LOG%
  if exist "%OUT_LOG%" type "%OUT_LOG%"
  exit /b 1
)

if exist "%TMP_JSON%" move /Y "%TMP_JSON%" "%OUT_JSON%" >nul
if exist "%TMP_LOG%" move /Y "%TMP_LOG%" "%OUT_LOG%" >nul

if exist "%OUT_JSON%" (
  for %%F in ("%OUT_JSON%") do if %%~zF==0 echo [] > "%OUT_JSON%"
)

echo TruffleHog JSON report written to %OUT_JSON%
