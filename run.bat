@echo off
REM Launch the interactive Bethesda Ghidra Scripts menu.
REM Double-click this file or run it from a terminal.
setlocal
cd /d "%~dp0"
chcp 65001 >nul 2>&1
set "PYTHONUTF8=1"

REM Find a tested 64-bit CPython.  Prefer the newest supported minor instead
REM of `py -3`, which may select an unsupported 3.15 prerelease.
set "PYEXE="
for %%V in (3.14 3.13 3.12 3.11) do (
    if not defined PYEXE (
        py -%%V -c "import sys; raise SystemExit(sys.maxsize.bit_length() != 63)" >nul 2>&1
        if not errorlevel 1 set "PYEXE=py -%%V"
    )
)
if not defined PYEXE (
    python -c "import sys; raise SystemExit(sys.version_info[:2] not in ((3,11),(3,12),(3,13),(3,14)) or sys.maxsize.bit_length() != 63)" >nul 2>&1 && set "PYEXE=python"
)

if not defined PYEXE (
    echo.
    echo A supported 64-bit CPython was not found.
    echo This tool supports CPython 3.11 through 3.14. Install it from:
    echo     https://www.python.org/downloads/
    py -3.15 -c "import sys; raise SystemExit(sys.maxsize.bit_length() != 63)" >nul 2>&1
    if not errorlevel 1 (
        echo.
        echo Python 3.15 was detected, but it is still a prerelease and the
        echo Ghidra/JPype bridge currently supports Python only through 3.14.
        echo Install Python 3.14 side-by-side; this launcher will select it.
    )
    echo Tick "Add python.exe to PATH" during Python setup, then run this file again.
    echo.
    pause
    exit /b 1
)

%PYEXE% "%~dp0run.py" %*
if errorlevel 1 (
    echo.
    echo run.py exited with an error.
    pause
)
endlocal
