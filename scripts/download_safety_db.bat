@echo off
setlocal

set "PYTHON_BIN=python"
if exist "%~dp0..\.venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0..\.venv\Scripts\python.exe"

set "OUTPUT_DIR=%~1"
if "%OUTPUT_DIR%"=="" set "OUTPUT_DIR=.tools\safety-db"

rem Pass remaining flags (e.g. --full, --no-verify-ssl) directly to the Python script
"%PYTHON_BIN%" "%~dp0download_safety_db.py" --output-dir "%OUTPUT_DIR%" %2 %3 %4

exit /b %ERRORLEVEL%
