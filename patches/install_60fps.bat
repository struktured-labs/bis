@echo off
setlocal

echo ============================================
echo  BIS 60fps Patch Installer
echo  Mario ^& Luigi: Bowser's Inside Story + BJJ
echo ============================================
echo.

:: Detect emulator data directory
set "AZAHAR=%APPDATA%\azahar-emu"
set "LIME=%APPDATA%\Lime3DS"
set "CITRA=%APPDATA%\Citra"

set "EMUDIR="
if exist "%AZAHAR%" set "EMUDIR=%AZAHAR%"
if exist "%LIME%" set "EMUDIR=%LIME%"
if exist "%CITRA%" set "EMUDIR=%CITRA%"

if "%EMUDIR%"=="" (
    echo Could not find emulator data folder.
    echo Checked: %AZAHAR%, %LIME%, %CITRA%
    echo.
    echo Please manually copy the correct .ips file to your emulator's mod folder:
    echo   load\mods\00040000001D1400\exefs\code.ips
    goto :ask_version
)

echo Found emulator at: %EMUDIR%

:: Check if update is installed (update title ID folder exists)
set "UPDATE_INSTALLED=0"
if exist "%EMUDIR%\sdmc\Nintendo 3DS\00000000000000000000000000000000\00000000000000000000000000000000\title\0004000e\001d1400" set "UPDATE_INSTALLED=1"

:: Set up mod directory
set "MODDIR=%EMUDIR%\load\mods\00040000001D1400\exefs"
if not exist "%MODDIR%" mkdir "%MODDIR%"

if "%UPDATE_INSTALLED%"=="1" (
    echo.
    echo Detected: Game update is installed (v1.1/v1.2)
    echo Installing update patch...
    copy /Y "%~dp0\60fps_update_v1.2.ips" "%MODDIR%\code.ips" >nul
    echo Done! Copied 60fps_update_v1.2.ips
) else (
    echo.
    echo Detected: Base game only (v1.0, no update)
    echo Installing base game patch...
    copy /Y "%~dp0\60fps.ips" "%MODDIR%\code.ips" >nul
    echo Done! Copied 60fps.ips
)

echo.
echo Patch installed to: %MODDIR%\code.ips
echo Launch the game to enjoy 60fps!
goto :end

:ask_version
echo.
echo Which version do you have?
echo   1) Base game (v1.0, no update installed)
echo   2) Updated game (v1.1 or v1.2)
echo.
set /p CHOICE="Enter 1 or 2: "

if "%CHOICE%"=="1" (
    echo.
    echo Use: 60fps.ips
    echo Copy it to: [emulator]\load\mods\00040000001D1400\exefs\code.ips
) else (
    echo.
    echo Use: 60fps_update_v1.2.ips
    echo Copy it to: [emulator]\load\mods\00040000001D1400\exefs\code.ips
)

:end
echo.
pause
