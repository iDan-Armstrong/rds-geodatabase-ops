@echo off
setlocal EnableExtensions
title rdsops launcher
cd /d "%~dp0"

rem ------------------------------------------------------------------
rem  rdsops launcher for Windows
rem  First run builds a private Python environment in .venv (git-ignored).
rem  Nothing here touches AWS until you run a command against an instance.
rem ------------------------------------------------------------------

set "VENV=%~dp0.venv"
set "RDSOPS=%VENV%\Scripts\rdsops.exe"

if not exist "%RDSOPS%" call :setup || goto :fail

:menu
cls
echo.
echo   ==================================================
echo    rdsops  ^|  geodatabase operations on Amazon RDS
echo   ==================================================
for /f "delims=" %%v in ('call "%RDSOPS%" --version') do echo    %%v   (%~dp0)
echo.
echo    1  Open the rdsops console
echo    2  Run the test suite (offline, no AWS needed)
echo    3  Update from GitHub, then reinstall
echo    4  Open the README
echo    5  Rebuild the Python environment
echo    Q  Quit
echo.
choice /c 12345Q /n /m "   Choose: "
if errorlevel 6 goto :eof
if errorlevel 5 (call :setup force & pause & goto :menu)
if errorlevel 4 (start "" "%~dp0README.md" & goto :menu)
if errorlevel 3 goto :update
if errorlevel 2 goto :tests
if errorlevel 1 goto :console
goto :menu

:console
cls
echo.
echo   rdsops console. The environment is active; type commands below.
echo.
echo   Examples:
echo     rdsops inventory --instance egdb-lab --profile lab
echo     rdsops health --host HOST --user USER --dbname egdb --iam --instance egdb-lab
echo     set RDSOPS_DSN=host=localhost dbname=egdb ^& rdsops maintenance --quiet
echo.
echo   AWS credentials come from your AWS profile or SSO login, never from here.
echo   Type EXIT to return to the menu.
echo.
cmd /k "call "%VENV%\Scripts\activate.bat" && prompt rdsops$G$S"
goto :menu

:tests
cls
"%VENV%\Scripts\python.exe" -m pytest -q
echo.
echo   Integration tests are skipped unless RDSOPS_TEST_DSN points at a PostGIS server.
pause
goto :menu

:update
cls
where git >nul 2>nul || (echo   git is not on PATH. & pause & goto :menu)
git pull --ff-only || (echo   Pull failed; local changes or no network. & pause & goto :menu)
call :setup force
pause
goto :menu

rem ------------------------------------------------------------------
:setup
rem Finds Python 3.11+ and installs rdsops into .venv
set "PY="
for %%c in ("py -3.13" "py -3.12" "py -3.11" "python") do (
    if not defined PY (
        %%~c -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul && set "PY=%%~c"
    )
)
if not defined PY (
    for %%p in ("%USERPROFILE%\anaconda3\python.exe" "%USERPROFILE%\miniconda3\python.exe" "%ProgramData%\anaconda3\python.exe" "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" "%LOCALAPPDATA%\Programs\Python\Python311\python.exe") do (
        if not defined PY if exist %%p (
            %%p -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul && set "PY=%%~p"
        )
    )
)
if not defined PY (
    echo.
    echo   Python 3.11 or newer was not found. Install it from python.org
    echo   ^(tick "Add python.exe to PATH"^), then run this launcher again.
    exit /b 1
)
if /i "%~1"=="force" if exist "%VENV%" rmdir /s /q "%VENV%"
echo.
echo   Setting up rdsops with: %PY%
if not exist "%VENV%\Scripts\python.exe" (
    "%PY%" -m venv "%VENV%" 2>nul || %PY% -m venv "%VENV%" || exit /b 1
)
"%VENV%\Scripts\python.exe" -m pip install --quiet --upgrade pip
"%VENV%\Scripts\python.exe" -m pip install --quiet -e ".[dev]" || exit /b 1
echo   Done.
exit /b 0

:fail
echo.
echo   Setup did not finish. Scroll up for the error.
pause
exit /b 1
