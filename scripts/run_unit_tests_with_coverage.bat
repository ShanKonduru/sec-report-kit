@echo off
setlocal

set "PYTHON_BIN=python"
if exist "%~dp0..\.venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0..\.venv\Scripts\python.exe"

set "COV_DIR=%~1"
if "%COV_DIR%"=="" set "COV_DIR=htmlcov"

echo Running unit tests with coverage...
"%PYTHON_BIN%" -m pytest --cov=sec_report_kit --cov-report=term-missing --cov-report=html:%COV_DIR% tests
if errorlevel 1 exit /b 1

echo Coverage HTML report written to %COV_DIR%\index.html
