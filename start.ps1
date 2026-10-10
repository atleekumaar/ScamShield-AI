# ScamShield AI - Windows Local Startup Script
# Starts FastAPI Backend (Port 8000) and Next.js Frontend (Port 3000)

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  🛡️  SCAMSHIELD AI - HACKATHON LAUNCHER (WIN)   " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# 1. Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Error "Python 3.12+ was not found on PATH. Please install Python."
    exit 1
}

# 2. Check Node & npm
$npmCmd = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npmCmd) {
    Write-Error "npm / Node.js was not found on PATH. Please install Node.js 18+."
    exit 1
}

# 3. Environment configuration
if (-not (Test-Path "backend\.env")) {
    Write-Host "[*] Creating backend\.env from template..." -ForegroundColor Yellow
    Copy-Item "backend\.env.example" "backend\.env"
}

Write-Host "`n[*] Starting FastAPI Backend on http://localhost:8000..." -ForegroundColor Green
$backendProcess = Start-Process python -ArgumentList "-m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload" -PassThru

Write-Host "[*] Starting Next.js Frontend on http://localhost:3000..." -ForegroundColor Green
$frontendProcess = Start-Process npm -ArgumentList "run dev" -WorkingDirectory "frontend" -PassThru

Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host "  SCAMSHIELD AI IS RUNNING:" -ForegroundColor White
Write-Host "  - Frontend SOC Dashboard: http://localhost:3000" -ForegroundColor Yellow
Write-Host "  - Backend REST API Docs:  http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "  - Health Check Endpoint:  http://localhost:8000/health" -ForegroundColor Yellow
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "Press Ctrl+C or close this terminal to stop services."

# Wait for process
try {
    Wait-Process -Id $backendProcess.Id, $frontendProcess.Id
} finally {
    Stop-Process -Id $backendProcess.Id -ErrorAction SilentlyContinue
    Stop-Process -Id $frontendProcess.Id -ErrorAction SilentlyContinue
}
