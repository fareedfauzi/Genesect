@echo off
setlocal EnableExtensions

set "SOURCE_DIR=%~dp0"
set "IDA_PLUGINS=C:\Program Files\IDA Pro 8.3\plugins"
set "TARGET_PACKAGE=%IDA_PLUGINS%\genesect"
set "LEGACY_BASE=pseudo"
set "LEGACY_BASE=%LEGACY_BASE%note"
set "LEGACY_PACKAGE=%LEGACY_BASE%_extended"
set "LEGACY_ENTRY=Pseudo"
set "LEGACY_ENTRY=%LEGACY_ENTRY%NoteExtended.py"

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

if not exist "%SOURCE_DIR%genesect\" (
    echo ERROR: Source package directory was not found:
    echo        %SOURCE_DIR%genesect
    goto :failed
)

if not exist "%SOURCE_DIR%Genesect.py" (
    echo ERROR: Source plugin entry point was not found:
    echo        %SOURCE_DIR%Genesect.py
    goto :failed
)

if not exist "%TARGET_PACKAGE%\" (
    mkdir "%TARGET_PACKAGE%" || goto :failed
)

echo Synchronizing new and modified Genesect files into:
echo   %TARGET_PACKAGE%
echo.

echo Cleaning up legacy installations...
if exist "%IDA_PLUGINS%\Genesect.py" del /F /Q "%IDA_PLUGINS%\Genesect.py"
if exist "%IDA_PLUGINS%\%LEGACY_ENTRY%" del /F /Q "%IDA_PLUGINS%\%LEGACY_ENTRY%"
if exist "%IDA_PLUGINS%\%LEGACY_BASE%.py" del /F /Q "%IDA_PLUGINS%\%LEGACY_BASE%.py"
if exist "%IDA_PLUGINS%\%LEGACY_BASE%\" rmdir /S /Q "%IDA_PLUGINS%\%LEGACY_BASE%"
if exist "%IDA_PLUGINS%\%LEGACY_PACKAGE%\" rmdir /S /Q "%IDA_PLUGINS%\%LEGACY_PACKAGE%"
if exist "%IDA_PLUGINS%\%LEGACY_BASE%.ini" del /F /Q "%IDA_PLUGINS%\%LEGACY_BASE%.ini"
if exist "%USERPROFILE%\.%LEGACY_BASE%.ini" del /F /Q "%USERPROFILE%\.%LEGACY_BASE%.ini"

rem Remove cached bytecode first so Python cannot import a feature whose source
rem module was removed. This cleanup is restricted to the dedicated package.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$target = $env:TARGET_PACKAGE; Get-ChildItem -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -eq '__pycache__' } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue; Get-ChildItem -LiteralPath $target -Recurse -File -Include '*.pyc','*.pyo' -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue"
if errorlevel 1 goto :failed

rem /MIR copies new/changed files and purges destination files/directories that
rem no longer exist in the current source tree.
robocopy "%SOURCE_DIR%genesect" "%TARGET_PACKAGE%" /MIR /R:2 /W:1 /COPY:DAT /DCOPY:DAT /XD __pycache__ /XF *.pyc *.pyo
if errorlevel 8 goto :failed

rem Keep IDA's root plugin entry point synchronized as well.
copy /Y "%SOURCE_DIR%Genesect.py" "%IDA_PLUGINS%\Genesect.py" >nul
if errorlevel 1 goto :failed

echo.
echo Installation completed successfully.
echo Restart IDA Pro before testing the updated plugin.
pause
exit /b 0

:failed
echo.
echo Installation failed. No additional files will be copied.
pause
exit /b 1
