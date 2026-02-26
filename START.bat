@echo off
:: ═══════════════════════════════════════════════════════════
::  CyberDrishti — Windows Startup Script (Fixed v2)
:: ═══════════════════════════════════════════════════════════

title CyberDrishti
chcp 65001 > nul
color 0B

echo.
echo  ================================================
echo   CyberDrishti - CERT-IN Cyber Exposure Scanner
echo   साइबर दृष्टि  -  Phase 0 Foundation
echo  ================================================
echo.

:: ── Step 1: Check Docker CLI is installed ────────────────────
echo [1/5] Checking Docker installation...
where docker > nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: Docker command not found.
    echo.
    echo  Please install Docker Desktop from:
    echo    https://www.docker.com/products/docker-desktop/
    echo.
    echo  After installing, restart your PC, then run START.bat again.
    echo.
    pause
    exit /b 1
)
echo        Docker CLI: OK

:: ── Step 2: Check Docker daemon ──────────────────────────────
echo [2/5] Checking if Docker Desktop is running...
docker ps > nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  Docker Desktop is not responding. Trying to start it...
    echo.
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe" 2>nul
    start "" "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" 2>nul
    echo  Waiting up to 90 seconds for Docker to start...
    echo.
    set WAIT=0
    :WAIT_LOOP
    timeout /t 5 /nobreak > nul
    set /a WAIT+=5
    echo  Checking... (%WAIT%s elapsed)
    docker ps > nul 2>&1
    if %errorlevel% equ 0 goto DOCKER_READY
    if %WAIT% lss 90 goto WAIT_LOOP
    echo.
    echo  Docker did not start in time.
    echo  Please open Docker Desktop manually, wait for the
    echo  whale icon in the taskbar to stop animating,
    echo  then run START.bat again.
    echo.
    pause
    exit /b 1
)
:DOCKER_READY
echo        Docker Desktop: Running

:: ── Step 3: Make sure we are in the right folder ─────────────
echo [3/5] Checking project files...
if not exist "%~dp0docker-compose.yml" (
    echo.
    echo  ERROR: docker-compose.yml not found.
    echo  You must run START.bat from INSIDE the cyberdrishti folder.
    echo  Current location: %CD%
    echo.
    pause
    exit /b 1
)
if not exist "%~dp0.env" (
    echo.
    echo  ERROR: .env file not found in: %~dp0
    echo.
    pause
    exit /b 1
)
if not exist "%~dp0docker\postgres\init.sql" (
    echo.
    echo  ERROR: docker\postgres\init.sql not found in: %~dp0
    echo.
    pause
    exit /b 1
)

:: Create directories if missing
if not exist "%~dp0logs" mkdir "%~dp0logs"
if not exist "%~dp0data" mkdir "%~dp0data"
echo        Project files: OK

:: ── Step 4: Move to project directory ────────────────────────
cd /d "%~dp0"
echo [4/5] Working directory: %CD%

:: ── Step 5: Start all containers ─────────────────────────────
echo [5/5] Starting CyberDrishti containers...
echo.
echo  On first run this downloads ~500MB of Docker images.
echo  This can take 5-10 minutes. Please wait...
echo.

docker compose up --build -d

if %errorlevel% neq 0 (
    echo.
    echo  ================================================
    echo   STARTUP FAILED - Troubleshooting:
    echo  ================================================
    echo.
    echo  1. See what went wrong:
    echo       docker compose logs
    echo.
    echo  2. Port already in use? Stop other services on
    echo     ports 8000, 5432, or 6379.
    echo.
    echo  3. Try a clean restart:
    echo       docker compose down
    echo       docker compose up --build -d
    echo.
    pause
    exit /b 1
)

echo.
echo  Containers started. Waiting for API to be ready...
timeout /t 15 /nobreak > nul

:: ── Done ─────────────────────────────────────────────────────
echo.
echo  ================================================
echo   CyberDrishti is RUNNING!
echo  ================================================
echo.
echo   Dashboard :  Open frontend\index.html in browser
echo   API Docs  :  http://localhost:8000/api/docs
echo   Health    :  http://localhost:8000/api/health
echo.
echo   To stop   :  Run STOP.bat
echo   Logs      :  docker compose logs -f
echo  ================================================
echo.

:: Open dashboard
start "" "%~dp0frontend\index.html"
echo  Dashboard opened in browser.
echo.
echo  This window can be closed. Services run in background.
echo.
echo  Press any key to tail live logs (Ctrl+C stops viewing, not services).
pause > nul
docker compose logs -f
