@echo off
REM Launch Watchtower. Uses the installed venv if present, else a dev .venv in this folder.
set "VENV=%LOCALAPPDATA%\Watchtower\venv"
if exist "%~dp0.venv\Scripts\python.exe" set "VENV=%~dp0.venv"
if not exist "%VENV%\Scripts\python.exe" (
    echo Watchtower is not installed. Run:  powershell -ExecutionPolicy Bypass -File "%~dp0install.ps1"
    exit /b 1
)
start "" "%VENV%\Scripts\pythonw.exe" -m watchtower %*
