#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Stop All Nexus IDPS Services
# ─────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${RED}[*] Stopping all Nexus IDPS background services...${NC}"

# Stop processes from PID file if available
if [ -f ".idps_pids" ]; then
    while read -r pid; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || sudo kill -9 "$pid" 2>/dev/null || true
        fi
    done < .idps_pids
    rm -f .idps_pids
fi

# Clean up by process name
sudo killall idps-backend 2>/dev/null || true
pkill -f "uvicorn.*5001" 2>/dev/null || true
pkill -f "vite.*5173" 2>/dev/null || true

# Release network ports
fuser -k 5173/tcp 2>/dev/null || true
fuser -k 5001/tcp 2>/dev/null || true
fuser -k 8000/tcp 2>/dev/null || true

echo -e "${GREEN}[+] All IDPS services (Dashboard, Backend, ML) stopped cleanly.${NC}"
