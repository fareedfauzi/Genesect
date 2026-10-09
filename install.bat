@echo off
setlocal EnableExtensions

echo ==========================================
echo   Genesect Installer (Windows)
echo ==========================================

set "SOURCE_DIR=%~dp0"
set "SOURCE_ENTRY=%SOURCE_DIR%Genesect.py"
set "SOURCE_PACKAGE=%SOURCE_DIR%genesect"

if not "%~1"=="" (
    set "IDA_PLUGINS=%~f1"
) else if defined IDAUSR (
    set "IDA_PLUGINS=%IDAUSR%\plugins"
) else if defined APPDATA (
    set "IDA_PLUGINS=%APPDATA%\Hex-Rays\IDA Pro\plugins"
) else (
    echo ERROR: Could not determine IDA plugins directory.
    exit /b 1
)

if not exist "%IDA_PLUGINS%\" mkdir "%IDA_PLUGINS%"

echo Target Directory: %IDA_PLUGINS%

echo [*] Cleaning up legacy installations...
set "LEGACY_ENTRY=Pseudo"
set "LEGACY_ENTRY=%LEGACY_ENTRY%NoteExtended.py"
set "LEGACY_BASE=pseudo"
set "LEGACY_BASE=%LEGACY_BASE%note"
if exist "%IDA_PLUGINS%\Genesect.py" del /F /Q "%IDA_PLUGINS%\Genesect.py"
if exist "%IDA_PLUGINS%\%LEGACY_ENTRY%" del /F /Q "%IDA_PLUGINS%\%LEGACY_ENTRY%"
if exist "%IDA_PLUGINS%\%LEGACY_BASE%.py" del /F /Q "%IDA_PLUGINS%\%LEGACY_BASE%.py"
if exist "%IDA_PLUGINS%\%LEGACY_BASE%\" rmdir /S /Q "%IDA_PLUGINS%\%LEGACY_BASE%"
if exist "%IDA_PLUGINS%\%LEGACY_BASE%.ini" del /F /Q "%IDA_PLUGINS%\%LEGACY_BASE%.ini"
if exist "%USERPROFILE%\.%LEGACY_BASE%.ini" del /F /Q "%USERPROFILE%\.%LEGACY_BASE%.ini"

if not exist "%SOURCE_ENTRY%" (
    echo ERROR: Cannot find local Genesect.py.
    echo Please use install.ps1 for remote installation:
    echo irm https://raw.githubusercontent.com/fareedfauzi/Genesect-Extended/main/install.ps1 ^| iex
    exit /b 1
)

echo [*] Copying files...
set "TARGET_PACKAGE=%IDA_PLUGINS%\genesect"
if exist "%TARGET_PACKAGE%\" rmdir /S /Q "%TARGET_PACKAGE%"
mkdir "%TARGET_PACKAGE%"

copy /Y "%SOURCE_ENTRY%" "%IDA_PLUGINS%\Genesect.py" >nul
robocopy "%SOURCE_PACKAGE%" "%TARGET_PACKAGE%" /E /R:0 /W:0 /XD __pycache__ /XF *.pyc *.pyo >nul

echo [*] Installation completed successfully.
echo [!] Please ensure Python dependencies are installed:
echo     pip install openai httpx PySide6
echo [*] Restart IDA Pro to load the updated plugin.
exit /b 0
