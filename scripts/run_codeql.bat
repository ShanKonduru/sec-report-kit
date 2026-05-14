@echo off
setlocal

set "REPO_ROOT=%~dp0.."
set "APP_PYTHON=python"
if exist "%REPO_ROOT%\.venv\Scripts\python.exe" set "APP_PYTHON=%REPO_ROOT%\.venv\Scripts\python.exe"

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "DATABASE_PATH=%~2"
if "%DATABASE_PATH%"=="" set "DATABASE_PATH=codeql-db"

set "QUERY_SUITE=%~3"
if "%QUERY_SUITE%"=="" set "QUERY_SUITE=codeql/python-queries"

set "OUT_JSON=%REPORT_DIR%\codeql.sarif.json"
set "CODEQL_CMD=codeql"
set "LOCAL_CODEQL_EXE=%~dp0..\.tools\bin\codeql\codeql.exe"
set "LOCAL_CODEQL_JAVA=%~dp0..\.tools\bin\codeql\tools\win64\java\bin\java.exe"

if exist "%LOCAL_CODEQL_EXE%" set "CODEQL_CMD=%LOCAL_CODEQL_EXE%"
set "CODEQL_CMD=%CODEQL_CMD:\"=%"
set "CODEQL_CMD=%CODEQL_CMD:'=%"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

where "%CODEQL_CMD%" >nul 2>&1
if errorlevel 1 if /I "%CODEQL_CMD%"=="codeql" (
  echo codeql not found. Attempting local install into .tools\bin...
  "%APP_PYTHON%" "%~dp0install_external_clis.py" --repo-root "%REPO_ROOT%" --tool codeql --force
  if errorlevel 1 (
    echo Failed to install CodeQL CLI.
    exit /b 1
  )
  if exist "%LOCAL_CODEQL_EXE%" set "CODEQL_CMD=%LOCAL_CODEQL_EXE%"
  set "CODEQL_CMD=%CODEQL_CMD:\"=%"
  set "CODEQL_CMD=%CODEQL_CMD:'=%"
  where "%CODEQL_CMD%" >nul 2>&1
  if errorlevel 1 if /I "%CODEQL_CMD%"=="codeql" (
    echo codeql is not installed or not on PATH.
    echo Install from: https://codeql.github.com/docs/codeql-overview/codeql-changelog/
    exit /b 1
  )
)

if exist "%LOCAL_CODEQL_EXE%" if not exist "%LOCAL_CODEQL_JAVA%" (
  echo Local CodeQL install appears incomplete ^(missing embedded Java^). Reinstalling CodeQL...
  "%APP_PYTHON%" "%~dp0install_external_clis.py" --repo-root "%REPO_ROOT%" --tool codeql --force
  if errorlevel 1 (
    echo Failed to reinstall CodeQL CLI.
    exit /b 1
  )
  if not exist "%LOCAL_CODEQL_JAVA%" (
    echo CodeQL reinstall completed, but embedded Java is still missing:
    echo   %LOCAL_CODEQL_JAVA%
    exit /b 1
  )
)

if not exist "%DATABASE_PATH%" (
  echo CodeQL database not found at %DATABASE_PATH%. Creating database...
  "%CODEQL_CMD%" database create "%DATABASE_PATH%" --language=python --source-root="%REPO_ROOT%"
  if errorlevel 1 (
    echo Failed to create CodeQL database at %DATABASE_PATH%
    exit /b 1
  )
)

"%CODEQL_CMD%" database finalize "%DATABASE_PATH%" >nul 2>&1

"%CODEQL_CMD%" database analyze "%DATABASE_PATH%" "%QUERY_SUITE%" --format=sarifv2.1.0 --output="%OUT_JSON%"
if errorlevel 1 exit /b 1

if not exist "%OUT_JSON%" (
  echo CodeQL analyze completed but did not produce output file:
  echo   %OUT_JSON%
  exit /b 1
)

echo CodeQL SARIF report written to %OUT_JSON%
