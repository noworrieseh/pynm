@echo off
REM Build script for creating standalone pynm executable on Windows
REM Usage: build.bat [--clean] [--debug]

setlocal enabledelayedexpansion

echo === Building pynm standalone executable ===

REM Parse arguments
set CLEAN=false
set DEBUG=false
for %%a in (%*) do (
    if "%%a"=="--clean" set CLEAN=true
    if "%%a"=="--debug" set DEBUG=true
)

REM Clean previous builds if requested
if "%CLEAN%"=="true" (
    echo Cleaning previous builds...
    if exist build rmdir /s /q build
    if exist dist rmdir /s /q dist
)

REM Check if PyInstaller is installed
python -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    python -m pip install pyinstaller
)

REM Build with PyInstaller
echo Building executable with PyInstaller...

if "%DEBUG%"=="true" (
    pyinstaller --clean --noconfirm pynm.spec --log-level DEBUG
) else (
    pyinstaller --clean --noconfirm pynm.spec
)

REM Verify build
if exist dist\pynm.exe (
    echo === Build successful! ===
    echo Executable: dist\pynm.exe
    dir dist\pynm.exe

    echo Testing executable...
    dist\pynm.exe --help

    REM Run tests AFTER successful build
    echo Running tests...
    python -m pytest tests -q
    echo Done!
) else (
    echo Build failed!
    exit /b 1
)

endlocal
