@echo off
setlocal EnableExtensions

rem PseudoNote Extended installer for any Windows IDA version.
rem Usage: install.bat [IDA_PLUGINS_DIRECTORY]

set "SOURCE_DIR=%~dp0"
set "SOURCE_ENTRY=%SOURCE_DIR%PseudoNoteExtended.py"
set "SOURCE_PACKAGE=%SOURCE_DIR%pseudonote_extended"

if /I "%~1"=="/h" goto :usage
if /I "%~1"=="-h" goto :usage
if /I "%~1"=="--help" goto :usage

if not "%~1"=="" (
    set "IDA_PLUGINS=%~f1"
) else if defined IDAUSR (
    set "IDA_PLUGINS=%IDAUSR%\plugins"
) else if defined APPDATA (
    set "IDA_PLUGINS=%APPDATA%\Hex-Rays\IDA Pro\plugins"
) else (
    echo ERROR: APPDATA is unavailable and IDAUSR is not set.
    echo Pass the IDA plugins directory explicitly.
    exit /b 1
)

if not exist "%SOURCE_ENTRY%" (
    echo ERROR: Missing source entry point: "%SOURCE_ENTRY%"
    exit /b 1
)
if not exist "%SOURCE_PACKAGE%\" (
    echo ERROR: Missing source package: "%SOURCE_PACKAGE%"
    exit /b 1
)

if not exist "%IDA_PLUGINS%\" mkdir "%IDA_PLUGINS%" || goto :failed
set "TARGET_PACKAGE=%IDA_PLUGINS%\pseudonote_extended"
if not exist "%TARGET_PACKAGE%\" mkdir "%TARGET_PACKAGE%" || goto :failed

echo Installing PseudoNote Extended into:
echo   %IDA_PLUGINS%
echo.

where robocopy.exe >nul 2>&1
if errorlevel 1 goto :xcopy

robocopy "%SOURCE_PACKAGE%" "%TARGET_PACKAGE%" /E /R:2 /W:1 /COPY:DAT /DCOPY:DAT /XD __pycache__ /XF *.pyc *.pyo >nul
if errorlevel 8 goto :failed
goto :copy_entry

:xcopy
xcopy "%SOURCE_PACKAGE%\*" "%TARGET_PACKAGE%\" /E /I /Y /Q /EXCLUDE:"%SOURCE_DIR%tools\install-excludes.txt" >nul
if errorlevel 1 goto :failed

:copy_entry
copy /Y "%SOURCE_ENTRY%" "%IDA_PLUGINS%\PseudoNoteExtended.py" >nul || goto :failed

echo Installation completed successfully.
echo Restart IDA to load the updated plugin.
exit /b 0

:usage
echo Usage: %~nx0 [IDA_PLUGINS_DIRECTORY]
echo.
echo With no argument, the installer uses:
echo   %%IDAUSR%%\plugins                  when IDAUSR is set
echo   %%APPDATA%%\Hex-Rays\IDA Pro\plugins otherwise
exit /b 0

:failed
echo ERROR: PseudoNote Extended installation failed.
exit /b 1
