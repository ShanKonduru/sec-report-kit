@echo off
setlocal

set "PYTHON_BIN=python"
if exist "%~dp0..\.venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0..\.venv\Scripts\python.exe"

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_NAME=%~2"
if "%TARGET_NAME%"=="" set "TARGET_NAME=sample-container-image"

set "IN_JSON=%REPORT_DIR%\trivy-image-report-v1.0.21.json"
set "OUT_HTML=%REPORT_DIR%\trivy-report.html"

if not exist "%IN_JSON%" (
  echo Missing input JSON: %IN_JSON%
  exit /b 1
)

"%PYTHON_BIN%" -m sec_report_kit render trivy --input "%IN_JSON%" --output "%OUT_HTML%" --target "%TARGET_NAME%"
if errorlevel 1 exit /b 1

echo HTML report written to %OUT_HTML%
for %%I in ("%OUT_HTML%") do set "OUT_HTML_ABS=%%~fI"
start "" "%OUT_HTML_ABS%"
