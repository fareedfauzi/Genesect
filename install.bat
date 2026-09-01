@echo off
setlocal EnableExtensions

echo ==========================================
echo   PseudoNote Extended Installer (Windows) 
echo ==========================================

set "SOURCE_DIR=%~dp0"
set "SOURCE_ENTRY=%SOURCE_DIR%PseudoNoteExtended.py"
set "SOURCE_PACKAGE=%SOURCE_DIR%pseudonote_extended"

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

echo [*] Cleaning up classic PseudoNote installations...
if exist "%IDA_PLUGINS%\pseudonote.py" del /F /Q "%IDA_PLUGINS%\pseudonote.py"
if exist "%IDA_PLUGINS%\pseudonote\" rmdir /S /Q "%IDA_PLUGINS%\pseudonote"
if exist "%IDA_PLUGINS%\pseudonote.ini" del /F /Q "%IDA_PLUGINS%\pseudonote.ini"
if exist "%USERPROFILE%\.pseudonote.ini" del /F /Q "%USERPROFILE%\.pseudonote.ini"

if not exist "%SOURCE_ENTRY%" (
    echo ERROR: Cannot find local PseudoNoteExtended.py. 
    echo Please use install.ps1 for remote installation:
    echo irm https://raw.githubusercontent.com/fareedfauzi/PseudoNote-Extended/main/install.ps1 ^| iex
    exit /b 1
)

echo [*] Copying files...
set "TARGET_PACKAGE=%IDA_PLUGINS%\pseudonote_extended"
if exist "%TARGET_PACKAGE%\" rmdir /S /Q "%TARGET_PACKAGE%"
mkdir "%TARGET_PACKAGE%"

copy /Y "%SOURCE_ENTRY%" "%IDA_PLUGINS%\PseudoNoteExtended.py" >nul
robocopy "%SOURCE_PACKAGE%" "%TARGET_PACKAGE%" /E /R:0 /W:0 /XD __pycache__ /XF *.pyc *.pyo >nul

echo [*] Installation completed successfully.
echo [!] Please ensure Python dependencies are installed:
echo     pip install openai httpx PySide6
echo [*] Restart IDA Pro to load the updated plugin.
exit /b 0
