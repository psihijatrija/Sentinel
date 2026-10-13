@echo off
setlocal enabledelayedexpansion
title Sentinel Build

echo ==============================================
echo    Sentinel - Building Minimum Installer
echo    (net48-windows, framework-dependent)
echo ==============================================

::  0. Read version from version.txt 
set "VERSION_FILE=%~dp0..\version.txt"
if not exist "%VERSION_FILE%" (
    echo ERROR: version.txt not found at %VERSION_FILE%
    exit /b 1
)
set /p VERSION=<"%VERSION_FILE%"
for /f "tokens=* delims= " %%V in ("%VERSION%") do set "VERSION=%%V"
echo Version: %VERSION%

::  0.1 + 0.2  Stamp csproj files and setup.iss 
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0_stamp.ps1" ^
    -Version "%VERSION%" ^
    -SrcDir "%~dp0..\src" ^
    -SetupIss "%~dp0setup.iss"
if errorlevel 1 ( echo ERROR: Version stamping failed & exit /b 1 )

::  1. Clean publish dir and old installers 
set "PUBLISH_DIR=%~dp0..\publish"
echo Cleaning publish outputs...
if exist "%PUBLISH_DIR%" rd /s /q "%PUBLISH_DIR%"

for %%F in ("%~dp0SentinelSetup-*.exe") do (
    if /i not "%%~nxF"=="SentinelSetup-%VERSION%.exe" (
        echo Removing old installer %%~nxF
        del /f /q "%%F"
    )
)
for %%F in ("%~dp0*.old") do del /f /q "%%F" 2>nul

::  2. Locate dotnet 
set "DOTNET=C:\Program Files\dotnet\dotnet.exe"
if not exist "%DOTNET%" set "DOTNET=dotnet"

::  3. Publish Service 
echo Publishing Sentinel Service (net48-windows, framework-dependent)...
"%DOTNET%" publish "%~dp0..\src\Sentinel.Service\Sentinel.Service.csproj" -c Release -f net48-windows -o "%PUBLISH_DIR%\service"
if errorlevel 1 ( echo ERROR: Service publish failed & exit /b 1 )

::  4. Publish Agent 
echo Publishing Sentinel Agent (net48-windows, framework-dependent)...
"%DOTNET%" publish "%~dp0..\src\Sentinel.Agent\Sentinel.Agent.csproj" -c Release -f net48-windows -o "%PUBLISH_DIR%\agent"
if errorlevel 1 ( echo ERROR: Agent publish failed & exit /b 1 )

::  4a. Icon and version.txt 
echo Deploying Sentinel.ico and version.txt...
set "ICON_SRC=%~dp0assets\Sentinel.ico"
if not exist "%ICON_SRC%" set "ICON_SRC=%~dp0..\assets\Sentinel.ico"
if exist "%ICON_SRC%" (
    copy /y "%ICON_SRC%" "%PUBLISH_DIR%\agent\Sentinel.ico"   >nul
    copy /y "%ICON_SRC%" "%PUBLISH_DIR%\service\Sentinel.ico" >nul
)
copy /y "%VERSION_FILE%" "%PUBLISH_DIR%\agent\version.txt"    >nul
copy /y "%VERSION_FILE%" "%PUBLISH_DIR%\service\version.txt"  >nul

::  4b. ML models (optional) 
set "ML_SRC=%~dp0..\src\Sentinel.Core\MlModels"
if exist "%ML_SRC%" (
    for %%T in (service agent) do (
        if not exist "%PUBLISH_DIR%\%%T\MlModels" md "%PUBLISH_DIR%\%%T\MlModels"
        for %%M in ("%ML_SRC%\*.zip") do (
            echo Copying ML model %%~nxM -^> %%T\MlModels
            copy /y "%%M" "%PUBLISH_DIR%\%%T\MlModels\" >nul
        )
    )
)

::  4c. LGPO.exe and GSecurity.inf (optional) 
set "HARDENING_SRC=%~dp0..\src\Sentinel.Core\HardeningResources"
for %%T in (service agent) do (
    for %%H in (LGPO.exe GSecurity.inf) do (
        if exist "%HARDENING_SRC%\%%H" (
            echo Copying %%H -^> %%T\
            copy /y "%HARDENING_SRC%\%%H" "%PUBLISH_DIR%\%%T\" >nul
        )
    )
)

::  5. Locate Inno Setup 
echo Locating Inno Setup compiler...
set "ISCC="
for %%P in (
    "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    "C:\Program Files\Inno Setup 6\ISCC.exe"
    "C:\Program Files (x86)\Inno Setup 7\ISCC.exe"
    "C:\Program Files\Inno Setup 7\ISCC.exe"
) do (
    if exist %%P ( set "ISCC=%%~P" & goto :found_iscc )
)
where ISCC.exe >nul 2>&1 && for /f "delims=" %%P in ('where ISCC.exe') do set "ISCC=%%P"
:found_iscc
if not defined ISCC (
    echo ERROR: Inno Setup compiler ^(ISCC.exe^) was not found.
    echo Install Inno Setup 6: https://jrsoftware.org/isdl.php
    exit /b 1
)
echo Found Inno Setup at: %ISCC%

::  6. Compile installer 
echo Compiling installer with Inno Setup...
if exist "%~dp0SentinelSetup-%VERSION%.exe" del /f /q "%~dp0SentinelSetup-%VERSION%.exe"
"%ISCC%" "%~dp0setup.iss"
if errorlevel 1 ( echo ERROR: ISCC failed & exit /b 1 )

if not exist "%~dp0SentinelSetup-%VERSION%.exe" (
    echo ERROR: Installer not produced at installer\SentinelSetup-%VERSION%.exe
    exit /b 1
)

::  7. Copy to releases\ 
set "RELEASES_DIR=%~dp0..\releases\%VERSION%"
if not exist "%RELEASES_DIR%" md "%RELEASES_DIR%"
move /y "%~dp0SentinelSetup-%VERSION%.exe" "%RELEASES_DIR%\" >nul
echo Copied installer to releases\%VERSION%\

echo ==============================================
echo Build completed successfully!
echo Installer: installer\SentinelSetup-%VERSION%.exe
echo Runtime:   .NET Framework 4.8 (framework-dependent)
echo ==============================================

endlocal
exit /b 0
