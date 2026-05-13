@echo off
setlocal

set "APP_PYTHON=python"
if exist "%~dp0..\.venv\Scripts\python.exe" set "APP_PYTHON=%~dp0..\.venv\Scripts\python.exe"

set "SCANNER_VENV=%~dp0..\.venv-scanners"
set "SCANNER_PYTHON=%SCANNER_VENV%\Scripts\python.exe"
set "TOOLS_BIN=%~dp0..\.tools\bin"
set "CODEQL_BIN=%~dp0..\.tools\bin\codeql"

REM Install app and dev dependencies in the primary project venv.
"%APP_PYTHON%" -m pip install --upgrade pip
if errorlevel 1 exit /b 1

"%APP_PYTHON%" -m pip install -e .[dev]
if errorlevel 1 exit /b 1

"%APP_PYTHON%" -m pip install pip-audit bandit
if errorlevel 1 exit /b 1

REM Create a dedicated scanner venv to avoid dependency conflicts with app tooling.
if not exist "%SCANNER_PYTHON%" (
	echo Creating scanner venv at %SCANNER_VENV%
	"%APP_PYTHON%" -m venv "%SCANNER_VENV%"
	if errorlevel 1 exit /b 1
)

"%SCANNER_PYTHON%" -m pip install --upgrade pip
if errorlevel 1 exit /b 1

"%SCANNER_PYTHON%" -m pip install semgrep checkov
if errorlevel 1 exit /b 1

REM Install external scanner CLIs into .tools\bin.
"%APP_PYTHON%" "%~dp0install_external_clis.py" --repo-root "%~dp0.."
set "CLI_EXIT=%errorlevel%"
if "%CLI_EXIT%"=="2" (
	echo.
	echo WARNING: External scanner CLIs could not be downloaded due to GitHub API rate limits.
	echo          Python packages ^(sec-report-kit, pip-audit, bandit, semgrep, checkov^) were installed successfully.
	echo          To install external CLIs, set GITHUB_TOKEN and re-run:
	echo            set GITHUB_TOKEN=^<your_token^>
	echo            python scripts\install_external_clis.py --repo-root .
	echo.
) else if "%CLI_EXIT%"=="1" (
	echo Failed to install one or more external scanner CLIs.
	exit /b 1
)

REM Make local tool directories available in current session immediately.
set "PATH=%TOOLS_BIN%;%CODEQL_BIN%;%PATH%"

REM Persist local tool directories in the user PATH for future terminals.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
	"$ErrorActionPreference='Stop';" ^
	"$tools=[System.IO.Path]::GetFullPath('%TOOLS_BIN%');" ^
	"$codeql=[System.IO.Path]::GetFullPath('%CODEQL_BIN%');" ^
	"$current=[Environment]::GetEnvironmentVariable('Path','User');" ^
	"if([string]::IsNullOrWhiteSpace($current)){ $current='' }" ^
	"$parts=@(); if($current){ $parts=$current.Split(';') | Where-Object { $_ -ne '' } }" ^
	"$set=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase);" ^
	"foreach($p in $parts){ [void]$set.Add($p) }" ^
	"$changed=$false;" ^
	"if($set.Add($tools)){ $parts += $tools; $changed=$true }" ^
	"if(Test-Path $codeql){ if($set.Add($codeql)){ $parts += $codeql; $changed=$true } }" ^
	"if($changed){ [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User') }"
if errorlevel 1 (
	echo Warning: failed to persist PATH updates. You can still run tools using scripts or full paths.
)

echo Installed in app venv ^(.venv^): sec-report-kit ^(editable^), dev tools, pip-audit, bandit.
echo Installed in scanner venv ^(.venv-scanners^): semgrep, checkov.
echo Installed external CLIs in .tools\bin: codeql, tfsec, gitleaks, trufflehog, osv-scanner.
echo Added local tool paths to PATH: %TOOLS_BIN% and %CODEQL_BIN%
