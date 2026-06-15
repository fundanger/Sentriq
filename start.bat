@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

if not exist ".env.local" (
  echo No .env.local found - run build.bat first.
  exit /b 1
)

if not exist ".next\standalone" (
  echo No production build found - running build.bat first.
  call build.bat
  if errorlevel 1 exit /b 1
)

for /f "usebackq eol=# tokens=1,* delims==" %%K in (".env.local") do (
  if not "%%K"=="" if not "%%L"=="" set "%%K=%%L"
)

node .next\standalone\server.js
