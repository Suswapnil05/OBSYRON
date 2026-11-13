@echo off
title OBSYRON // HackInnovision 2026 Track C
echo ===============================================================
echo   OBSYRON - Attack Graph Forensics & Forensic AI Platform
echo   HackInnovision 2026 - Track C: Cybersecurity Investigation
echo ===============================================================
echo.

set "PY_EXE=python"
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
)

echo [1/2] Verifying Python environment...
"%PY_EXE%" --version
echo.
echo [2/2] Launching OBSYRON Server at http://localhost:8000 ...
echo Open your web browser and navigate to: http://localhost:8000
echo.
"%PY_EXE%" app.py
pause

