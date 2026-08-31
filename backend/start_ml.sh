#!/bin/bash
# ──────────────────────────────────────────────
# IDPS ML Service Launcher
# Starts the Python FastAPI ML inference service
# ──────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/.venv"
ML_SERVER="$SCRIPT_DIR/ml_server.py"
MODEL_PATH="$PROJECT_ROOT/idps_model.keras"
SCALER_PATH="$PROJECT_ROOT/idps_scaler.pkl"

echo "===================================="
echo "  IDPS ML Service Launcher"
echo "===================================="

# Check model files exist
if [ ! -f "$MODEL_PATH" ]; then
    echo "ERROR: Model file not found at $MODEL_PATH"
    echo "Please place your trained idps_model.keras in the project root."
    exit 1
fi
if [ ! -f "$SCALER_PATH" ]; then
    echo "WARNING: Scaler file not found at $SCALER_PATH"
    echo "Inference will fall back to log-scaling. For best results, place idps_scaler.pkl in the project root."
fi

# Create/activate virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python virtual environment using Python 3.12..."
    python3.12 -m venv "$VENV_DIR"
fi

echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Install dependencies
echo "Installing dependencies (this may take a few minutes)..."
pip install --default-timeout=1000 --quiet fastapi uvicorn tensorflow numpy pydantic scikit-learn

# Export model paths
export ML_MODEL_PATH="$MODEL_PATH"
export ML_SCALER_PATH="$SCALER_PATH"

echo ""
echo "Starting ML service..."
echo "  Health check: http://localhost:5001/health"
echo "  Predict:      POST http://localhost:5001/predict"
echo ""

# Run the server
python "$ML_SERVER"
