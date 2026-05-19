@echo off
REM Master script to run all security scans one by one
REM Each scan launches in a new command window
REM Opens the consolidated HTML report at the end

setlocal enabledelayedexpansion

cd /d "%~dp0\.."

echo.
echo ========================================
echo Running All Security Scans
echo ========================================
echo.

set REPORT_DIR=security_reports
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

REM Use absolute path for report directory
for %%I in ("%~dp0..") do set "PROJECT_ROOT=%%~fI"
set "REPORT_DIR=%PROJECT_ROOT%\security_reports"
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

REM Run Bandit
echo Starting: Bandit scan...
start "Bandit Scan" /wait cmd /c "cd /d %CD%\scripts && call run_bandit.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: Bandit scan
echo Rendering Bandit report...
call scripts\render_bandit_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Run Checkov
echo Starting: Checkov scan...
start "Checkov Scan" /wait cmd /c "cd /d %CD%\scripts && call run_checkov.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: Checkov scan
echo Rendering Checkov report...
call scripts\render_checkov_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Run CodeQL
echo Starting: CodeQL scan...
start "CodeQL Scan" /wait cmd /c "cd /d %CD%\scripts && call run_codeql.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: CodeQL scan
echo Rendering CodeQL report...
call scripts\render_codeql_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Run Gitleaks
echo Starting: Gitleaks scan...
start "Gitleaks Scan" /wait cmd /c "cd /d %CD%\scripts && call run_gitleaks.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: Gitleaks scan
echo Rendering Gitleaks report...
call scripts\render_gitleaks_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Run OSV Scanner
echo Starting: OSV Scanner scan...
start "OSV Scanner Scan" /wait cmd /c "cd /d %CD%\scripts && call run_osv_scanner.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: OSV Scanner scan
echo Rendering OSV Scanner report...
call scripts\render_osv_scanner_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Run Pip Audit
echo Starting: Pip Audit scan...
start "Pip Audit Scan" /wait cmd /c "cd /d %CD%\scripts && call run_pip_audit.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: Pip Audit scan
echo Rendering Pip Audit report...
call scripts\render_pip_audit_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Run Safety
echo Starting: Safety scan...
start "Safety Scan" /wait cmd /c "cd /d %CD%\scripts && call run_safety.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: Safety scan
echo Rendering Safety report...
call scripts\render_safety_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Run Semgrep
echo Starting: Semgrep scan...
start "Semgrep Scan" /wait cmd /c "cd /d %CD%\scripts && call run_semgrep.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: Semgrep scan
echo Rendering Semgrep report...
call scripts\render_semgrep_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Run Tfsec
echo Starting: Tfsec scan...
start "Tfsec Scan" /wait cmd /c "cd /d %CD%\scripts && call run_tfsec.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: Tfsec scan
echo Rendering Tfsec report...
call scripts\render_tfsec_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Run Trivy
echo Starting: Trivy scan...
start "Trivy Scan" /wait cmd /c "cd /d %CD%\scripts && call run_trivy.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: Trivy scan
echo Rendering Trivy report...
call scripts\render_trivy_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Run Trufflehog
echo Starting: Trufflehog scan...
start "Trufflehog Scan" /wait cmd /c "cd /d %CD%\scripts && call run_trufflehog.bat "%REPORT_DIR%" "%PROJECT_ROOT%""
echo Completed: Trufflehog scan
echo Rendering Trufflehog report...
call scripts\render_trufflehog_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo.

REM Generate consolidated report
echo.
echo ========================================
echo Generating Consolidated Report
echo ========================================
echo.
echo Rendering: Consolidated Security Report
call scripts\render_consolidated_html.bat "%REPORT_DIR%" "%PROJECT_ROOT%"
echo Completed: Consolidated Report
echo.

echo.
echo ========================================
echo All Security Scans Complete
echo ========================================
echo.

endlocal
