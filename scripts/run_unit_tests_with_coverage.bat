@echo off
setlocal

set "PYTHON_BIN=python"
set "PYTEST_EXE="
if exist "%~dp0..\.venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0..\.venv\Scripts\python.exe"
if exist "%~dp0..\.venv\Scripts\pytest.exe" set "PYTEST_EXE=%~dp0..\.venv\Scripts\pytest.exe"

set "COV_DIR=%~1"
if "%COV_DIR%"=="" set "COV_DIR=htmlcov"
if "%COV_DIR%"=="." set "COV_DIR=htmlcov"
if "%COV_DIR%"==".\" set "COV_DIR=htmlcov"

pushd "%~dp0.." >nul

echo Running unit tests with coverage...
if not "%PYTEST_EXE%"=="" (
	"%PYTEST_EXE%" --cov=sec_report_kit --cov-report=term-missing --cov-report=html:%COV_DIR% tests
) else (
	"%PYTHON_BIN%" -m pytest --cov=sec_report_kit --cov-report=term-missing --cov-report=html:%COV_DIR% tests
)
set "TEST_EXIT=%ERRORLEVEL%"

popd >nul
if %TEST_EXIT% NEQ 0 exit /b %TEST_EXIT%

echo Coverage HTML report written to %COV_DIR%\index.html
