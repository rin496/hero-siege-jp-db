@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
title Hero Siege Master

set "GAME_DIR=E:\SteamLibrary\steamapps\common\HeroSiege"
set "BASE=%LOCALAPPDATA%\HeroSiegeMaster"
set "SCRIPT=%BASE%\hero_siege_master.py"
set "LOG=%BASE%\updater.log"
set "TMP=%BASE%\hero_siege_master.download.py"
set "API=https://api.github.com/repos/rin496/hero-siege-jp-db/contents/tools/hero_siege_master.py?ref=main"

if not exist "%BASE%" mkdir "%BASE%"

> "%LOG%" echo [%date% %time%] Hero Siege Master updater
>>"%LOG%" echo GAME_DIR=%GAME_DIR%
>>"%LOG%" echo SCRIPT=%SCRIPT%

echo ========================================
echo Hero Siege Master
echo ========================================
echo.
echo [1/3] Downloading current Master from GitHub...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
 "$ErrorActionPreference='Stop';" ^
 "$h=@{'User-Agent'='HeroSiegeMasterUpdater';'Accept'='application/vnd.github+json';'Cache-Control'='no-cache';'Pragma'='no-cache'};" ^
 "$u='%API%&ts=' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();" ^
 "$r=Invoke-RestMethod -Headers $h -Uri $u;" ^
 "$bytes=[Convert]::FromBase64String(($r.content -replace '\s',''));" ^
 "[IO.File]::WriteAllBytes('%TMP%',$bytes);" ^
 "$text=[Text.Encoding]::UTF8.GetString($bytes);" ^
 "$m=[regex]::Match($text,'(?:MASTER_VERSION|VERSION)\s*=\s*[''\""]([^''\""]+)[''\""]');" ^
 "if(-not $m.Success){throw 'Version marker not found in downloaded Master'};" ^
 "Write-Host ('Remote blob: ' + $r.sha);" ^
 "Write-Host ('Remote version: ' + $m.Groups[1].Value);" ^
 "Add-Content -Encoding UTF8 '%LOG%' ('remote_blob=' + $r.sha);" ^
 "Add-Content -Encoding UTF8 '%LOG%' ('remote_version=' + $m.Groups[1].Value)" 

if errorlevel 1 (
  echo.
  echo ERROR: Latest Master could not be downloaded.
  echo The old local copy will NOT be run, to prevent stale results.
  echo Log: %LOG%
  pause
  exit /b 1
)

copy /y "%TMP%" "%SCRIPT%" >nul
del /q "%TMP%" >nul 2>&1

echo.
echo [2/3] Verifying local Master...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
 "$text=Get-Content -Raw -Encoding UTF8 '%SCRIPT%';" ^
 "$m=[regex]::Match($text,'(?:MASTER_VERSION|VERSION)\s*=\s*[''\""]([^''\""]+)[''\""]');" ^
 "if(-not $m.Success){exit 2};" ^
 "Write-Host ('Local version: ' + $m.Groups[1].Value);" ^
 "Add-Content -Encoding UTF8 '%LOG%' ('local_version=' + $m.Groups[1].Value)"

if errorlevel 1 (
  echo ERROR: Downloaded Master failed verification.
  pause
  exit /b 1
)

where py >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python launcher ^(py^) was not found.
  pause
  exit /b 1
)

if not exist "%GAME_DIR%\bin\Hero_Siege.exe" if not exist "%GAME_DIR%\Hero_Siege.exe" (
  echo ERROR: Hero Siege was not found at:
  echo %GAME_DIR%
  pause
  exit /b 1
)

echo.
echo [3/3] Running Master...
py "%SCRIPT%" "%GAME_DIR%"
set "RESULT=%ERRORLEVEL%"
>>"%LOG%" echo result=%RESULT%

if not "%RESULT%"=="0" (
  echo.
  echo Master failed with exit code %RESULT%.
  echo Log: %LOG%
  pause
  exit /b %RESULT%
)

echo.
echo Analysis completed.

if exist "%USERPROFILE%\Desktop\hero_siege_master" (
  copy /y "%LOG%" "%USERPROFILE%\Desktop\hero_siege_master\updater.log" >nul
  start "" "%USERPROFILE%\Desktop\hero_siege_master"
)
if exist "%USERPROFILE%\OneDrive\Desktop\hero_siege_master" (
  copy /y "%LOG%" "%USERPROFILE%\OneDrive\Desktop\hero_siege_master\updater.log" >nul
  start "" "%USERPROFILE%\OneDrive\Desktop\hero_siege_master"
)

echo.
echo The updater intentionally refuses to run a stale local Master.
echo Upload hero_siege_master.zip to ChatGPT.
pause
