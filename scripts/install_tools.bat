@echo off
setlocal

REM Install this project and pip-audit in the active Python environment.
python -m pip install --upgrade pip
if errorlevel 1 exit /b 1

python -m pip install -e .
if errorlevel 1 exit /b 1

python -m pip install pip-audit
if errorlevel 1 exit /b 1

echo Installed sec-report-kit (editable) and pip-audit.
