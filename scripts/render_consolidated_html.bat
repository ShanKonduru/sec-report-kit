@echo off
setlocal

set "PYTHON_BIN=python"
if exist "%~dp0..\.venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0..\.venv\Scripts\python.exe"
set "PYTHONPATH=%~dp0..\src;%PYTHONPATH%"

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_NAME=%~2"
if "%TARGET_NAME%"=="" for %%I in ("%~dp0..") do set "TARGET_NAME=%%~nxI"

if not "%~1"=="" shift
if not "%~1"=="" shift

set "EXTRA_ARGS="
:collect_args
if "%~1"=="" goto after_collect_args
set "EXTRA_ARGS=%EXTRA_ARGS% "%~1""
shift
goto collect_args
:after_collect_args

if not exist "%REPORT_DIR%" (
  echo Missing input directory: %REPORT_DIR%
  exit /b 1
)

set "OUT_HTML=%REPORT_DIR%\consolidated-security-report.html"

"%PYTHON_BIN%" -m sec_report_kit render consolidated --input "%REPORT_DIR%" --output "%REPORT_DIR%" --target "%TARGET_NAME%" %EXTRA_ARGS%
if errorlevel 1 exit /b 1

echo HTML report written to %OUT_HTML%
for %%I in ("%OUT_HTML%") do set "OUT_HTML_ABS=%%~fI"
start "" "%OUT_HTML_ABS%"
