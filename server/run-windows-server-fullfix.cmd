@echo off
setlocal

rem PHP2Shell full check/repair launcher for the Windows Server host itself.
rem Put this file and php2shell-fullfix-windows.ps1 in the same directory.

net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo Requesting administrator privileges...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b
)

set "SCRIPT=%~dp0php2shell-fullfix-windows.ps1"
if not exist "%SCRIPT%" (
    echo Missing php2shell-fullfix-windows.ps1
    pause
    exit /b 1
)

echo This operation runs on the current Windows Server host.
echo Default is check-only. Pass -Apply only after creating a full server snapshot.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
set "RC=%errorlevel%"
echo.
echo Exit code: %RC%
pause
exit /b %RC%
