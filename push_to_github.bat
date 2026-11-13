@echo off
title Push OBSYRON to GitHub
echo ===============================================================
echo   Pushing OBSYRON to GitHub (Suswapnil05/OBSYRON)
echo ===============================================================
echo.
cd /d "d:\HACK INNOVISION"

echo Current git status:
git status -s
echo.
echo Pushing to https://github.com/Suswapnil05/OBSYRON.git ...
git push -u origin main
echo.
if %ERRORLEVEL% EQU 0 (
    echo ===============================================================
    echo   SUCCESS! Pushed cleanly to GitHub:
    echo   https://github.com/Suswapnil05/OBSYRON
    echo ===============================================================
) else (
    echo.
    echo If prompted to authenticate, please complete the sign-in in your browser.
)
echo.
pause

