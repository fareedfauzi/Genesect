@echo off
setlocal EnableExtensions

set "SOURCE_DIR=%~dp0"
set "IDA_PLUGINS=C:\Program Files\IDA Professional 9.3\plugins"
set "TARGET_PACKAGE=%IDA_PLUGINS%\pseudonote_extended"

rem Program Files normally requires elevation. Relaunch this script as admin.
fltmc >nul 2>&1
if errorlevel 1 (
    echo Requesting Administrator permission to update the IDA plugins folder...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -Verb RunAs -Wait"
    exit /b
)

if not exist "%IDA_PLUGINS%\" (
    echo ERROR: IDA plugins directory was not found:
    echo        %IDA_PLUGINS%
    goto :failed
)

if not exist "%SOURCE_DIR%pseudonote_extended\" (
    echo ERROR: Source package directory was not found:
    echo        %SOURCE_DIR%pseudonote_extended
    goto :failed
)

if not exist "%SOURCE_DIR%PseudoNoteExtended.py" (
    echo ERROR: Source plugin entry point was not found:
    echo        %SOURCE_DIR%PseudoNoteExtended.py
    goto :failed
)

if not exist "%TARGET_PACKAGE%\" (
    mkdir "%TARGET_PACKAGE%" || goto :failed
)

echo Synchronizing new and modified PseudoNote Extended files into:
echo   %TARGET_PACKAGE%
echo.

echo Cleaning up classic PseudoNote installations...
if exist "%IDA_PLUGINS%\pseudonote.py" del /F /Q "%IDA_PLUGINS%\pseudonote.py"
if exist "%IDA_PLUGINS%\pseudonote\" rmdir /S /Q "%IDA_PLUGINS%\pseudonote"
if exist "%IDA_PLUGINS%\pseudonote.ini" del /F /Q "%IDA_PLUGINS%\pseudonote.ini"
if exist "%USERPROFILE%\.pseudonote.ini" del /F /Q "%USERPROFILE%\.pseudonote.ini"

rem Remove cached bytecode first so Python cannot import a feature whose source
rem module was removed. This cleanup is restricted to the dedicated package.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$target = $env:TARGET_PACKAGE; Get-ChildItem -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -eq '__pycache__' } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue; Get-ChildItem -LiteralPath $target -Recurse -File -Include '*.pyc','*.pyo' -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue"
if errorlevel 1 goto :failed

rem /MIR copies new/changed files and purges destination files/directories that
rem no longer exist in the current source tree.
robocopy "%SOURCE_DIR%pseudonote_extended" "%TARGET_PACKAGE%" /MIR /R:2 /W:1 /COPY:DAT /DCOPY:DAT /XD __pycache__ /XF *.pyc *.pyo
if errorlevel 8 goto :failed

rem Keep IDA's root plugin entry point synchronized as well.
copy /Y "%SOURCE_DIR%PseudoNoteExtended.py" "%IDA_PLUGINS%\PseudoNoteExtended.py" >nul
if errorlevel 1 goto :failed

echo.
echo Installation completed successfully.
echo Restart IDA Pro before testing the updated plugin.
exit /b 0

:failed
echo.
echo Installation failed. No additional files will be copied.

exit /b 1
