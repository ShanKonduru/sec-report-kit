@echo off
setlocal

set "PYTHON_BIN=python"
if exist "%~dp0..\.venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0..\.venv\Scripts\python.exe"
set "PYTHONWARNINGS=ignore"

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "REQ_FILE=%~2"
set "OUT_JSON=%REPORT_DIR%\safety.json"

rem --- Resolve local DB path relative to project root (parent of scripts/) ---
set "LOCAL_DB_DIR=%~dp0..\.tools\safety-db"
set "LOCAL_DB_FLAG="
if exist "%LOCAL_DB_DIR%\insecure.json" (
  set "LOCAL_DB_FLAG=--db "%LOCAL_DB_DIR%""
  echo Using local Safety DB at %LOCAL_DB_DIR%
) else (
  echo No local Safety DB found. Attempting online scan.
  echo Run scripts\download_safety_db.bat to cache the DB for offline use.
)

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"
if exist "%OUT_JSON%" del /f /q "%OUT_JSON%" >nul 2>&1

if "%REQ_FILE%"=="" (
  "%PYTHON_BIN%" -W ignore -m safety check --json %LOCAL_DB_FLAG% --save-json "%OUT_JSON%" >nul 2>nul
) else (
  "%PYTHON_BIN%" -W ignore -m safety check --json --file "%REQ_FILE%" %LOCAL_DB_FLAG% --save-json "%OUT_JSON%" >nul 2>nul
)
set "SAFETY_EXIT=%ERRORLEVEL%"

if not exist "%OUT_JSON%" (
  if "%SAFETY_EXIT%"=="68" (
    echo Safety CLI could not reach the server ^(exit code 68^) and no JSON report was produced.
    echo Tip: Run scripts\download_safety_db.bat while online to enable offline scanning.
  ) else (
    echo Safety CLI failed with exit code %SAFETY_EXIT% and produced no JSON output.
  )
  exit /b %SAFETY_EXIT%
)

"%PYTHON_BIN%" -c "import json,sys; json.load(open(sys.argv[1], encoding='utf-8'))" "%OUT_JSON%" >nul 2>&1
if errorlevel 1 (
  if "%SAFETY_EXIT%"=="68" (
    echo Safety CLI could not reach the server ^(exit code 68^); output file is not valid JSON.
    echo Tip: Run scripts\download_safety_db.bat while online to enable offline scanning.
  ) else (
    echo Safety CLI output is not valid JSON ^(exit code %SAFETY_EXIT%^).
  )
  exit /b %SAFETY_EXIT%
)

if not "%SAFETY_EXIT%"=="0" (
  echo Safety CLI returned exit code %SAFETY_EXIT%. Valid JSON report was still generated.
)

echo Safety JSON report written to %OUT_JSON%