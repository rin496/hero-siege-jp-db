@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
title Hero Siege Master Auto Updater

set "GAME_DIR=E:\SteamLibrary\steamapps\common\HeroSiege"
set "SCRIPT=%~dp0hero_siege_master.py"
set "SELF=%~f0"
set "TMP_SCRIPT=%TEMP%\hero_siege_master_latest_%RANDOM%.py"
set "TMP_BAT=%TEMP%\run_master_latest_%RANDOM%.bat"
set "API_MASTER=https://api.github.com/repos/rin496/hero-siege-jp-db/contents/tools/hero_siege_master.py?ref=main"
set "API_BAT=https://api.github.com/repos/rin496/hero-siege-jp-db/contents/tools/run_master.bat?ref=main"

echo ========================================
echo Hero Siege Master Auto Updater
echo ========================================
echo.

echo [0/4] Checking launcher update...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop';$h=@{'User-Agent'='HeroSiegeMasterUpdater';'Accept'='application/vnd.github+json';'Cache-Control'='no-cache'};$u='%API_BAT%&nocache=' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$r=Invoke-RestMethod -Headers $h -Uri $u;$bytes=[Convert]::FromBase64String(($r.content -replace '\s',''));[IO.File]::WriteAllBytes('%TMP_BAT%',$bytes)" >nul 2>&1
if not errorlevel 1 (
  fc /b "%SELF%" "%TMP_BAT%" >nul 2>&1
  if errorlevel 1 (
    echo Launcher update found. Replacing and restarting...
    copy /y "%TMP_BAT%" "%SELF%" >nul
    del /q "%TMP_BAT%" >nul 2>&1
    start "" cmd /c ""%SELF%""
    exit /b 0
  )
)
del /q "%TMP_BAT%" >nul 2>&1

echo [1/4] Checking latest Master...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop';$h=@{'User-Agent'='HeroSiegeMasterUpdater';'Accept'='application/vnd.github+json';'Cache-Control'='no-cache'};$u='%API_MASTER%&nocache=' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$r=Invoke-RestMethod -Headers $h -Uri $u;$bytes=[Convert]::FromBase64String(($r.content -replace '\s',''));[IO.File]::WriteAllBytes('%TMP_SCRIPT%',$bytes);Write-Host ('Master blob: ' + $r.sha)"
if errorlevel 1 (
  echo GitHub API check failed.
  if not exist "%SCRIPT%" (pause&exit /b 1)
  echo Using local Master.
) else (
  if exist "%SCRIPT%" (
    fc /b "%SCRIPT%" "%TMP_SCRIPT%" >nul 2>&1
    if errorlevel 1 (copy /y "%TMP_SCRIPT%" "%SCRIPT%" >nul&echo Master updated.) else echo Master is already current.
  ) else (copy /y "%TMP_SCRIPT%" "%SCRIPT%" >nul&echo Master downloaded.)
)
del /q "%TMP_SCRIPT%" >nul 2>&1

echo.
echo [2/4] Checking environment...
where py >nul 2>&1 || (echo Python launcher ^(py^) was not found.&pause&exit /b 1)
if not exist "%GAME_DIR%\bin\Hero_Siege.exe" if not exist "%GAME_DIR%\Hero_Siege.exe" (echo Hero Siege was not found at:&echo %GAME_DIR%&pause&exit /b 1)

echo.
echo [3/4] Local Master version:
powershell -NoProfile -ExecutionPolicy Bypass -Command "$m=Select-String -Path '%SCRIPT%' -Pattern '(MASTER_VERSION|VERSION)\s*=\s*[\"''][^\"'']+[\"'']' | Select-Object -First 1;if($m){Write-Host ('  ' + $m.Matches[0].Value)}else{Write-Host '  unknown'}"

echo.
echo [4/4] Running Master...
py "%SCRIPT%" "%GAME_DIR%"
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" (echo Master exited with error code %RESULT%.&pause&exit /b %RESULT%)

echo.
echo Analysis completed.
if exist "%USERPROFILE%\Desktop\hero_siege_master" start "" "%USERPROFILE%\Desktop\hero_siege_master"
if exist "%USERPROFILE%\OneDrive\Desktop\hero_siege_master" start "" "%USERPROFILE%\OneDrive\Desktop\hero_siege_master"
echo Upload hero_siege_master.zip to ChatGPT.
pause
