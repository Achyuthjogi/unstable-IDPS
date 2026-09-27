#!/bin/bash

# Define colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Ensure PATH includes ~/.local/bin and /usr/local/bin, even under sudo
if [ -n "$SUDO_USER" ]; then
    SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    export PATH="$SUDO_USER_HOME/.local/bin:$SUDO_USER_HOME/bin:$PATH"
fi
export PATH="$HOME/.local/bin:$HOME/bin:/usr/local/bin:$PATH"

# Fallback: check ~/.local/share/nodejs if npm is still not found
if ! command -v npm >/dev/null 2>&1; then
    for node_dir in "$HOME/.local/share/nodejs"/node-*/bin "${SUDO_USER_HOME:-$HOME}/.local/share/nodejs"/node-*/bin; do
        if [ -x "$node_dir/npm" ]; then
            export PATH="$node_dir:$PATH"
            break
        fi
    done
fi

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}  Starting Ultimate IDPS (Full Stack)     ${NC}"
echo -e "${BLUE}==========================================${NC}"

echo ""
echo "Select IDPS Interface Mode:"
echo "1) Web Interface (Browser)"
echo "2) Terminal Dashboard (CLI)"
read -p "Enter choice [1 or 2]: " UI_MODE

if [ "$UI_MODE" != "1" ] && [ "$UI_MODE" != "2" ]; then
    echo -e "${RED}Invalid choice. Defaulting to Web Interface (1).${NC}"
    UI_MODE="1"
fi
echo ""

# Pre-cache sudo for CLI mode so it can run backend in bg
if [ "$UI_MODE" = "2" ] && [ "$EUID" -ne 0 ]; then
    echo -e "${GREEN}--> Caching sudo credentials for background packet engine...${NC}"
    sudo -v
fi

# Verify npm availability (Only needed for Web Mode)
if [ "$UI_MODE" = "1" ] && ! command -v npm >/dev/null 2>&1; then
    echo -e "${RED}ERROR: 'npm' command not found!${NC}"
    echo -e "Please install Node.js and npm (e.g. 'sudo dnf install -y nodejs npm')."
    exit 1
fi

# Function to clean up background processes on exit
cleanup() {
    echo -e "\n${RED}Shutting down IDPS services...${NC}"
    if [ -n "$FRONTEND_PID" ]; then
        kill -- -$FRONTEND_PID 2>/dev/null || kill $FRONTEND_PID 2>/dev/null || true
    fi
    if [ -n "$ML_PID" ]; then
        kill $ML_PID 2>/dev/null || true
    fi
    if [ "$UI_MODE" = "2" ]; then
        sudo killall idps-backend 2>/dev/null || true
    fi
    # Free ports
    fuser -k 5173/tcp 2>/dev/null || true
    fuser -k 5001/tcp 2>/dev/null || true
    echo -e "${GREEN}Services stopped safely.${NC}"
    exit 0
}

# Trap Ctrl+C (SIGINT) and SIGTERM to run the cleanup function
trap cleanup SIGINT SIGTERM

# Free ports if leftover from previous crashed runs
fuser -k 5173/tcp 2>/dev/null || true
fuser -k 5001/tcp 2>/dev/null || true

# Prepare logs directory and ensure proper permissions
mkdir -p logs
if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
    chown -R "$SUDO_USER" logs 2>/dev/null || true
fi
chmod -R 777 logs 2>/dev/null || true

# 1. Start ML Service in background
echo -e "${GREEN}--> Starting Python ML Microservice...${NC}"
bash backend/start_ml.sh > logs/ml.log 2>&1 &
ML_PID=$!

# Wait for ML service to be responsive
echo -n "    Waiting for ML Engine on port 5001..."
ML_READY=false
for i in {1..45}; do
    if curl -s http://localhost:5001/health >/dev/null 2>&1; then
        echo -e " ${GREEN}[READY]${NC}"
        ML_READY=true
        break
    fi
    sleep 1
    echo -n "."
done

if [ "$ML_READY" = false ]; then
    echo -e " ${RED}[FAILED]${NC}"
    echo -e "${RED}--> Error: ML Microservice failed to respond on port 5001.${NC}"
    echo -e "${RED}    Check logs/ml.log:${NC}"
    tail -n 15 logs/ml.log 2>/dev/null
fi

# 2. Start React Frontend in background (Only if Web Mode)
FRONTEND_READY=false
if [ "$UI_MODE" = "1" ]; then
    echo -e "${GREEN}--> Starting React Frontend...${NC}"
    cd frontend
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" env PATH="$PATH" npm run dev > ../logs/frontend.log 2>&1 &
        FRONTEND_PID=$!
    else
        npm run dev > ../logs/frontend.log 2>&1 &
        FRONTEND_PID=$!
    fi
    cd ..

    # Wait for Frontend to be responsive
    echo -n "    Waiting for Frontend on port 5173..."
    for i in {1..15}; do
        if curl -s http://localhost:5173 >/dev/null 2>&1; then
            echo -e " ${GREEN}[READY]${NC}"
            FRONTEND_READY=true
            break
        fi
        sleep 1
        echo -n "."
    done

    if [ "$FRONTEND_READY" = false ]; then
        echo -e " ${RED}[FAILED]${NC}"
        echo -e "${RED}--> Error: React Frontend failed to start on port 5173.${NC}"
        echo -e "${RED}    Check logs/frontend.log:${NC}"
        tail -n 15 logs/frontend.log 2>/dev/null
    fi
fi

echo ""
echo -e "${BLUE}==========================================${NC}"
if [ "$UI_MODE" = "1" ]; then
    if [ "$FRONTEND_READY" = true ]; then
        echo -e "${GREEN}  [+] Frontend UI:  http://localhost:5173 ${NC}"
    else
        echo -e "${RED}  [!] Frontend UI:  http://localhost:5173 (FAILED - check logs/frontend.log)${NC}"
    fi
else
    echo -e "${GREEN}  [+] Interface:    Terminal Dashboard (CLI) ${NC}"
fi
echo -e "${GREEN}  [+] Go Backend:   http://localhost:8000 ${NC}"
if [ "$ML_READY" = true ]; then
    echo -e "${GREEN}  [+] ML Engine:    http://localhost:5001 ${NC}"
else
    echo -e "${RED}  [!] ML Engine:    http://localhost:5001 (FAILED - check logs/ml.log)${NC}"
fi
echo -e "${BLUE}==========================================${NC}"
if [ "$UI_MODE" = "1" ]; then
    echo -e "  Logs: logs/ml.log | logs/frontend.log"
else
    echo -e "  Logs: logs/ml.log | logs/backend.log"
fi
echo ""

# Auto-open browser if Frontend is running and desktop is available
if [ "$UI_MODE" = "1" ] && [ "$FRONTEND_READY" = true ] && command -v xdg-open >/dev/null 2>&1; then
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" xdg-open http://localhost:5173 >/dev/null 2>&1 &
    else
        xdg-open http://localhost:5173 >/dev/null 2>&1 &
    fi
fi

# 3. Compile and Start Go Backend (and CLI if mode 2)
cd backend

echo -e "${GREEN}--> Compiling Go Backend...${NC}"
go build -o idps-backend .

if [ "$UI_MODE" = "2" ]; then
    echo -e "${GREEN}--> Compiling CLI Dashboard...${NC}"
    go build -o idps-cli cmd/cli/main.go
fi

echo -e "${GREEN}--> Starting Go Packet Engine (sudo required)...${NC}"
echo -e "    Press Ctrl+C at any time to safely shut down all services."

if [ "$UI_MODE" = "1" ]; then
    # Run Backend in foreground for Web Mode
    if [ "$EUID" -eq 0 ]; then
        GODEBUG=cgocheck=0 ./idps-backend
    else
        sudo GODEBUG=cgocheck=0 ./idps-backend
    fi
else
    # Run Backend in background for CLI Mode
    if [ "$EUID" -eq 0 ]; then
        GODEBUG=cgocheck=0 ./idps-backend > ../logs/backend.log 2>&1 &
    else
        sudo GODEBUG=cgocheck=0 ./idps-backend > ../logs/backend.log 2>&1 &
    fi
    
    echo -e "${GREEN}--> Waiting for Backend API...${NC}"
    sleep 2

    # Start CLI in foreground
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" ./idps-cli
    else
        ./idps-cli
    fi
fi

# If the Go backend or CLI exits on its own, clean up the other services
cleanup
