@echo off
setlocal

set "REPO_ROOT=%~dp0.."
set "APP_PYTHON=python"
if exist "%REPO_ROOT%\.venv\Scripts\python.exe" set "APP_PYTHON=%REPO_ROOT%\.venv\Scripts\python.exe"

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_PATH=%~2"
if "%TARGET_PATH%"=="" set "TARGET_PATH=."

set "OUT_JSON=%REPORT_DIR%\osv-scanner.json"
set "OSV_CMD=osv-scanner"

if exist "%~dp0..\.tools\bin\osv-scanner.exe" set "OSV_CMD=%~dp0..\.tools\bin\osv-scanner.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

where "%OSV_CMD%" >nul 2>&1
if errorlevel 1 if /I "%OSV_CMD%"=="osv-scanner" (
  echo osv-scanner not found. Attempting local install into .tools\bin...
  "%APP_PYTHON%" "%~dp0install_external_clis.py" --repo-root "%REPO_ROOT%"
  if exist "%~dp0..\.tools\bin\osv-scanner.exe" set "OSV_CMD=%~dp0..\.tools\bin\osv-scanner.exe"
  where "%OSV_CMD%" >nul 2>&1
  if errorlevel 1 if /I "%OSV_CMD%"=="osv-scanner" (
    echo osv-scanner is not installed or not on PATH.
    echo Install from: https://github.com/google/osv-scanner
    exit /b 1
  )
)

set "TMP_JSON=%TEMP%\srk-osv-%RANDOM%-%RANDOM%.json"

rem Build scan args: prefer explicit lockfile sources over bare directory walk
set "OSV_ARGS=--format json --output-file "%TMP_JSON%""

set "FOUND_SOURCE=0"
if exist "%REPO_ROOT%\requirements.txt"   set "OSV_ARGS=%OSV_ARGS% --lockfile "%REPO_ROOT%\requirements.txt""   & set "FOUND_SOURCE=1"
if exist "%REPO_ROOT%\requirements-dev.txt" set "OSV_ARGS=%OSV_ARGS% --lockfile "%REPO_ROOT%\requirements-dev.txt"" & set "FOUND_SOURCE=1"
if exist "%REPO_ROOT%\poetry.lock"        set "OSV_ARGS=%OSV_ARGS% --lockfile "%REPO_ROOT%\poetry.lock""        & set "FOUND_SOURCE=1"
if exist "%REPO_ROOT%\Pipfile.lock"       set "OSV_ARGS=%OSV_ARGS% --lockfile "%REPO_ROOT%\Pipfile.lock""       & set "FOUND_SOURCE=1"
if exist "%REPO_ROOT%\uv.lock"            set "OSV_ARGS=%OSV_ARGS% --lockfile "%REPO_ROOT%\uv.lock""            & set "FOUND_SOURCE=1"
if exist "%REPO_ROOT%\pdm.lock"           set "OSV_ARGS=%OSV_ARGS% --lockfile "%REPO_ROOT%\pdm.lock""           & set "FOUND_SOURCE=1"

if "%FOUND_SOURCE%"=="0" (
  echo No supported lockfile found. Generating requirements.txt from installed packages...
  "%APP_PYTHON%" -m pip freeze > "%REPO_ROOT%\requirements.txt"
  if errorlevel 1 (
    echo Failed to generate requirements.txt. Skipping OSV scan.
    echo [] > "%OUT_JSON%"
    exit /b 0
  )
  echo Generated %REPO_ROOT%\requirements.txt
  set "OSV_ARGS=%OSV_ARGS% --lockfile "%REPO_ROOT%\requirements.txt""
  set "FOUND_SOURCE=1"
)

"%OSV_CMD%" scan %OSV_ARGS%
set "OSV_EXIT=%ERRORLEVEL%"

if not exist "%TMP_JSON%" echo [] > "%TMP_JSON%"
move /Y "%TMP_JSON%" "%OUT_JSON%" >nul

rem Exit code 1 = vulnerabilities found; 127 = no package sources found — both are non-error outcomes
if "%OSV_EXIT%"=="1" (
  echo OSV-Scanner JSON report written to %OUT_JSON% ^(vulnerabilities found^)
  exit /b 0
)
if "%OSV_EXIT%"=="127" (
  echo OSV-Scanner found no scannable package sources. No supported lockfile detected.
  exit /b 0
)
if "%OSV_EXIT%" NEQ "0" (
  echo OSV-Scanner failed with exit code %OSV_EXIT%
  exit /b %OSV_EXIT%
)

echo OSV-Scanner JSON report written to %OUT_JSON%
