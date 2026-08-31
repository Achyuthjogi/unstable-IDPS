#!/bin/bash

# Define colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}  Starting Ultimate IDPS (Full Stack)     ${NC}"
echo -e "${BLUE}==========================================${NC}"

# Function to clean up background processes on exit
cleanup() {
    echo -e "\n${RED}Shutting down IDPS services...${NC}"
    if [ -n "$ML_PID" ]; then
        kill $ML_PID 2>/dev/null
    fi
    if [ -n "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null
    fi
    echo -e "${GREEN}Services stopped safely.${NC}"
    exit 0
}

# Trap Ctrl+C (SIGINT) and SIGTERM to run the cleanup function
trap cleanup SIGINT SIGTERM

# 1. Start ML Service in background
echo -e "${GREEN}--> Starting Python ML Microservice...${NC}"
bash backend/start_ml.sh > /dev/null 2>&1 &
ML_PID=$!
# Give it a couple seconds to boot
sleep 3

# 2. Start React Frontend in background
echo -e "${GREEN}--> Starting React Frontend...${NC}"
cd frontend
npm run dev > /dev/null 2>&1 &
FRONTEND_PID=$!
cd ..
# Give it a second to boot
sleep 2

echo -e "${BLUE}==========================================${NC}"
echo -e "${GREEN}  [+] Frontend URL: http://localhost:5173 ${NC}"
echo -e "${GREEN}  [+] Go Backend:   http://localhost:8080 ${NC}"
echo -e "${GREEN}  [+] ML Engine:    http://localhost:5001 ${NC}"
echo -e "${BLUE}==========================================${NC}"
echo ""

# 3. Start Go Backend in foreground (Needs sudo for packet sniffing)
echo -e "${GREEN}--> Starting Go Packet Engine (sudo required)...${NC}"
echo -e "    Press Ctrl+C at any time to safely shut down all services."
cd backend
sudo go run main.go

# If the Go backend exits on its own, clean up the other services
cleanup
