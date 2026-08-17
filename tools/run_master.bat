@echo off
setlocal EnableExtensions
chcp 65001 >nul

title Hero Siege Master Updater

set "GAME_DIR=E:\SteamLibrary\steamapps\common\HeroSiege"
set "SCRIPT=%~dp0hero_siege_master.py"
set "TEMP_SCRIPT=%TEMP%\hero_siege_master_latest.py"
set "RAW_URL=https://raw.githubusercontent.com/rin496/hero-siege-jp-db/main/tools/hero_siege_master.py"

echo ========================================
echo Hero Siege Master
 echo ========================================
echo.

echo [1/3] Checking latest Master...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Invoke-WebRequest -UseBasicParsing -Uri '%RAW_URL%' -OutFile '%TEMP_SCRIPT%'; exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"

if errorlevel 1 (
    echo.
    echo Could not check GitHub.
    if not exist "%SCRIPT%" (
        echo No local Master is available, so execution cannot continue.
        pause
        exit /b 1
    )
    echo Using the existing local Master.
) else (
    if exist "%SCRIPT%" (
        fc /b "%SCRIPT%" "%TEMP_SCRIPT%" >nul 2>&1
        if errorlevel 1 (
            copy /y "%TEMP_SCRIPT%" "%SCRIPT%" >nul
            echo Master updated.
        ) else (
            echo Master is already up to date.
        )
    ) else (
        copy /y "%TEMP_SCRIPT%" "%SCRIPT%" >nul
        echo Master downloaded.
    )
)

del /q "%TEMP_SCRIPT%" >nul 2>&1

echo.
echo [2/3] Checking Python...
where py >nul 2>&1
if errorlevel 1 (
    echo Python launcher ^(py^) was not found.
    echo Install Python, then run this BAT again.
    pause
    exit /b 1
)

if not exist "%GAME_DIR%\bin\Hero_Siege.exe" if not exist "%GAME_DIR%\Hero_Siege.exe" (
    echo Hero Siege was not found at:
    echo %GAME_DIR%
    pause
    exit /b 1
)

echo.
echo [3/3] Running Master...
py "%SCRIPT%" "%GAME_DIR%"
set "RESULT=%ERRORLEVEL%"

echo.
if not "%RESULT%"=="0" (
    echo Master exited with error code %RESULT%.
    pause
    exit /b %RESULT%
)

echo Analysis completed.
echo Result ZIP: %%USERPROFILE%%\Desktop\hero_siege_master.zip

if exist "%USERPROFILE%\Desktop\hero_siege_master" start "" "%USERPROFILE%\Desktop\hero_siege_master"
if exist "%USERPROFILE%\OneDrive\Desktop\hero_siege_master" start "" "%USERPROFILE%\OneDrive\Desktop\hero_siege_master"

echo.
echo You can now upload hero_siege_master.zip to ChatGPT.
pause
