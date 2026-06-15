@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

if not exist ".env.local" (
  echo No .env.local found - creating one from .env.example
  copy /y ".env.example" ".env.local" >nul

  for /f "delims=" %%K in ('node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"') do set ENCKEY=%%K
  for /f "delims=" %%S in ('node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"') do set AUTHSECRET=%%S

  powershell -NoProfile -Command "(Get-Content '.env.local') -replace '^ENCRYPTION_KEY=$', 'ENCRYPTION_KEY=%ENCKEY%' -replace '^AUTH_SECRET=$', 'AUTH_SECRET=%AUTHSECRET%' | Set-Content '.env.local'"

  echo Generated .env.local with random ENCRYPTION_KEY and AUTH_SECRET.
)

echo Installing dependencies...
call npm install
if errorlevel 1 exit /b 1

set NEEDS_SEED=0
if not exist "data\sentriq.db" set NEEDS_SEED=1

echo Applying database schema...
call npm run db:push
if errorlevel 1 exit /b 1

if "%NEEDS_SEED%"=="1" (
  echo Seeding database...
  call npm run db:seed
  if errorlevel 1 exit /b 1
)

echo Building Sentriq...
call npm run build
if errorlevel 1 exit /b 1

echo Build complete. Run start.bat to launch Sentriq.
