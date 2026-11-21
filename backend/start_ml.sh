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
MODEL_PATH="$PROJECT_ROOT/zero_day_model.joblib"
SCALER_PATH="$PROJECT_ROOT/feature_scaler.joblib"

# Ensure PATH includes user local bin even if executed via sudo
if [ -n "$SUDO_USER" ]; then
    SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    export PATH="$SUDO_USER_HOME/.local/bin:$SUDO_USER_HOME/bin:$PATH"
fi
export PATH="$HOME/.local/bin:$HOME/bin:/usr/local/bin:$PATH"

echo "===================================="
echo "  IDPS ML Service Launcher"
echo "===================================="

# Check model files exist
if [ ! -f "$MODEL_PATH" ]; then
    echo "ERROR: Model file not found at $MODEL_PATH"
    echo "Please place your trained zero_day_model.joblib in the project root."
    exit 1
fi
if [ ! -f "$SCALER_PATH" ]; then
    echo "WARNING: Scaler file not found at $SCALER_PATH"
    echo "Inference will fall back to log-scaling. For best results, place feature_scaler.joblib in the project root."
fi

# Create/activate virtual environment
VENV_PYTHON="$VENV_DIR/bin/python"
if [ ! -d "$VENV_DIR" ] || [ ! -x "$VENV_PYTHON" ] || ! "$VENV_PYTHON" -c "exit(0)" >/dev/null 2>&1; then
    echo "Configuring Python virtual environment..."
    rm -rf "$VENV_DIR"
    PYTHON_BIN=""
    if command -v python3.12 >/dev/null 2>&1; then
        PYTHON_BIN="python3.12"
    elif command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="python3"
    fi

    if [ -n "$PYTHON_BIN" ]; then
        $PYTHON_BIN -m venv --system-site-packages "$VENV_DIR"
        "$VENV_DIR/bin/python" -m ensurepip --default-pip >/dev/null 2>&1 || true
    else
        echo "ERROR: python3 was not found in PATH."
        exit 1
    fi
fi

echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Install dependencies only if needed
if ! python -c "import fastapi, uvicorn, pydantic, joblib" >/dev/null 2>&1; then
    echo "Installing missing ML dependencies..."
    pip install --default-timeout=1000 --quiet fastapi uvicorn joblib numpy pydantic scikit-learn pandas || true
fi

# Export model paths
export ML_MODEL_PATH="$MODEL_PATH"
export ML_SCALER_PATH="$SCALER_PATH"

echo ""
echo "Starting ML service..."
echo "  Health check: http://localhost:5001/health"
echo "  Predict:      POST http://localhost:5001/predict"
echo ""

# Run the server
exec python "$ML_SERVER"
