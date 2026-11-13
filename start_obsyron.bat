@echo off
title OBSYRON // HackInnovision 2026 Track C
echo ===============================================================
echo   OBSYRON - Attack Graph Forensics & Forensic AI Platform
echo   HackInnovision 2026 - Track C: Cybersecurity Investigation
echo ===============================================================
echo.
echo [1/2] Verifying Python environment...
python --version
echo.
echo [2/2] Launching OBSYRON Server at http://localhost:8000 ...
echo Open your web browser and navigate to: http://localhost:8000
echo.
python app.py
pause

