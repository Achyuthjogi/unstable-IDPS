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
MODEL_PATH="$PROJECT_ROOT/idps_ml_model.pkl"

echo "===================================="
echo "  IDPS ML Service Launcher"
echo "===================================="

# Check model file exists
if [ ! -f "$MODEL_PATH" ]; then
    echo "ERROR: Model file not found at $MODEL_PATH"
    echo "Please place your trained idps_ml_model.pkl in the project root."
    exit 1
fi

# Create/activate virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Install dependencies
echo "Installing dependencies..."
pip install --quiet fastapi uvicorn scikit-learn joblib numpy

# Export model path
export ML_MODEL_PATH="$MODEL_PATH"

echo ""
echo "Starting ML service..."
echo "  Health check: http://localhost:5001/health"
echo "  Predict:      POST http://localhost:5001/predict"
echo ""

# Run the server
python "$ML_SERVER"
