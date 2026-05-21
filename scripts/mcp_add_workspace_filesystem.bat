@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "PROFILE=%~1"
if "%PROFILE%"=="" set "PROFILE=shan_s_mcp_hub"

set "TARGET_PATH=%~2"
if "%TARGET_PATH%"=="" set "TARGET_PATH=%~dp0.."

for %%I in ("%TARGET_PATH%") do set "ABS_PATH=%%~fI"

where docker >nul 2>nul
if errorlevel 1 (
	echo ERROR: docker CLI was not found in PATH.
	exit /b 1
)

echo Using profile: %PROFILE%
echo Allowing path: %ABS_PATH%

set "SERVER_REF=catalog://mcp/docker-mcp-catalog/filesystem"
docker mcp profile server add "%PROFILE%" --server "%SERVER_REF%" >nul 2>nul
if errorlevel 1 (
	echo Filesystem server may already exist in profile. Continuing...
) else (
	echo Added filesystem server to profile.
)

set "ESCAPED_PATH=%ABS_PATH:\=\\%"
docker mcp profile config "%PROFILE%" --set "filesystem.paths=[%ESCAPED_PATH%]"
if errorlevel 1 (
	echo ERROR: failed to set filesystem.paths.
	exit /b 1
)

echo.
echo Done. Current filesystem.paths value:
docker mcp profile config "%PROFILE%" --get filesystem.paths
if errorlevel 1 exit /b 1

echo.
echo Example:
echo   %~nx0 shan_s_mcp_hub C:\MyProjects\sec-report-kit
