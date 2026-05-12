@echo off
setlocal

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "DATABASE_PATH=%~2"
if "%DATABASE_PATH%"=="" set "DATABASE_PATH=codeql-db"

set "QUERY_SUITE=%~3"
if "%QUERY_SUITE%"=="" set "QUERY_SUITE=codeql/python-queries"

set "OUT_JSON=%REPORT_DIR%\codeql.sarif.json"
set "CODEQL_CMD=codeql"

if exist "%~dp0..\.tools\bin\codeql\codeql.exe" set "CODEQL_CMD=%~dp0..\.tools\bin\codeql\codeql.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

where "%CODEQL_CMD%" >nul 2>&1
if errorlevel 1 if /I "%CODEQL_CMD%"=="codeql" (
  echo codeql is not installed or not on PATH.
  echo Install from: https://codeql.github.com/docs/codeql-overview/codeql-changelog/
  exit /b 1
)

"%CODEQL_CMD%" database analyze "%DATABASE_PATH%" "%QUERY_SUITE%" --format=sarifv2.1.0 --output="%OUT_JSON%"
if errorlevel 1 exit /b 1

echo CodeQL SARIF report written to %OUT_JSON%
