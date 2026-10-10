#!/usr/bin/env bash
# ScamShield AI - Linux/macOS Local Startup Script
# Starts FastAPI Backend (Port 8000) and Next.js Frontend (Port 3000)

set -e

echo "================================================="
echo "  🛡️  SCAMSHIELD AI - HACKATHON LAUNCHER (UNIX)   "
echo "================================================="

if ! command -v python3 &> /dev/null; then
    echo "[-] Python 3.12+ was not found. Please install Python."
    exit 1
fi

if ! command -v npm &> /dev/null; then
    echo "[-] npm was not found. Please install Node.js 18+."
    exit 1
fi

if [ ! -f "backend/.env" ]; then
    echo "[*] Creating backend/.env from template..."
    cp backend/.env.example backend/.env
fi

cleanup() {
    echo -e "\n[*] Stopping services..."
    kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "[*] Starting FastAPI Backend on http://localhost:8000..."
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

echo "[*] Starting Next.js Frontend on http://localhost:3000..."
(cd frontend && npm run dev) &
FRONTEND_PID=$!

echo ""
echo "================================================="
echo "  SCAMSHIELD AI IS RUNNING:"
echo "  - Frontend SOC Dashboard: http://localhost:3000"
echo "  - Backend REST API Docs:  http://localhost:8000/docs"
echo "  - Health Check Endpoint:  http://localhost:8000/health"
echo "================================================="
echo "Press Ctrl+C to terminate services."

wait
