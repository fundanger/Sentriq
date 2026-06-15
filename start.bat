@echo off
cd /d "%~dp0"

if not exist ".env.local" (
  echo No .env.local found - run build.bat first.
  exit /b 1
)

if not exist ".next" (
  echo No production build found - running build.bat first.
  call build.bat
  if errorlevel 1 exit /b 1
)

call npm run start
