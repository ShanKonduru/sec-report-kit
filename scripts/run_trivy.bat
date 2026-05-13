@echo off
setlocal

set "REPORT_DIR=%~1"
if "%REPORT_DIR%"=="" set "REPORT_DIR=security_reports"

set "TARGET_IMAGE=%~2"
if "%TARGET_IMAGE%"=="" set "TARGET_IMAGE=alpine:latest"

set "OUT_JSON=%REPORT_DIR%\trivy-image-report-v1.0.21.json"
set "TRIVY_CMD=trivy"

if exist "%~dp0..\.tools\bin\trivy.exe" set "TRIVY_CMD=%~dp0..\.tools\bin\trivy.exe"

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

where "%TRIVY_CMD%" >nul 2>&1
if errorlevel 1 if /I "%TRIVY_CMD%"=="trivy" (
  echo trivy is not installed or not on PATH.
  echo Install from: https://github.com/aquasecurity/trivy
  exit /b 1
)

"%TRIVY_CMD%" image --format json --output "%OUT_JSON%" "%TARGET_IMAGE%"
if errorlevel 1 exit /b 1

echo Trivy JSON report written to %OUT_JSON%
