@echo off
setlocal

set "PYTHON_BIN=python"
if exist "%~dp0..\.venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0..\.venv\Scripts\python.exe"

REM Install this project, test tools, and pip-audit in the active Python environment.
"%PYTHON_BIN%" -m pip install --upgrade pip
if errorlevel 1 exit /b 1

"%PYTHON_BIN%" -m pip install -e .[dev]
if errorlevel 1 exit /b 1

"%PYTHON_BIN%" -m pip install pip-audit
if errorlevel 1 exit /b 1

echo Installed sec-report-kit (editable), dev tools, and pip-audit.
