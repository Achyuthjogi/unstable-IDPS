#!/usr/bin/env python3
"""
IDPS ML Inference Microservice (Production-Ready)
Loads the trained DNN model + StandardScaler and serves predictions via FastAPI on port 5001.
"""
import os, sys, warnings, pickle
import numpy as np
warnings.filterwarnings("ignore", category=UserWarning)

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import tensorflow as tf

MODEL_PATH = os.environ.get("ML_MODEL_PATH", os.path.join(os.path.dirname(__file__), "..", "idps_model.keras"))
SCALER_PATH = os.environ.get("ML_SCALER_PATH", os.path.join(os.path.dirname(__file__), "..", "idps_scaler.pkl"))
PORT = int(os.environ.get("ML_SERVICE_PORT", "5001"))

# Load Model
print(f"Loading ML model from: {MODEL_PATH}")
try:
    model = tf.keras.models.load_model(MODEL_PATH)
    print(f"Model loaded!")
except Exception as e:
    print(f"FATAL: Failed to load ML model: {e}", file=sys.stderr)
    sys.exit(1)

# Load Scaler
scaler = None
print(f"Loading scaler from: {SCALER_PATH}")
try:
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    print("Scaler loaded!")
except Exception as e:
    print(f"WARNING: No scaler found ({e}). Will use log-scale fallback.", file=sys.stderr)

app = FastAPI(title="IDPS ML Inference Service", version="2.0.0")

# 78 feature fields matching CIC-IDS-2017
class FlowFeatures(BaseModel):
    destination_port: float = 0.0
    flow_duration: float = 0.0
    total_fwd_packets: float = 0.0
    total_backward_packets: float = 0.0
    total_length_of_fwd_packets: float = 0.0
    total_length_of_bwd_packets: float = 0.0
    fwd_packet_length_max: float = 0.0
    fwd_packet_length_min: float = 0.0
    fwd_packet_length_mean: float = 0.0
    fwd_packet_length_std: float = 0.0
    bwd_packet_length_max: float = 0.0
    bwd_packet_length_min: float = 0.0
    bwd_packet_length_mean: float = 0.0
    bwd_packet_length_std: float = 0.0
    flow_bytes_per_s: float = 0.0
    flow_packets_per_s: float = 0.0
    flow_iat_mean: float = 0.0
    flow_iat_std: float = 0.0
    flow_iat_max: float = 0.0
    flow_iat_min: float = 0.0
    fwd_iat_total: float = 0.0
    fwd_iat_mean: float = 0.0
    fwd_iat_std: float = 0.0
    fwd_iat_max: float = 0.0
    fwd_iat_min: float = 0.0
    bwd_iat_total: float = 0.0
    bwd_iat_mean: float = 0.0
    bwd_iat_std: float = 0.0
    bwd_iat_max: float = 0.0
    bwd_iat_min: float = 0.0
    fwd_psh_flags: float = 0.0
    bwd_psh_flags: float = 0.0
    fwd_urg_flags: float = 0.0
    bwd_urg_flags: float = 0.0
    fwd_header_length: float = 0.0
    bwd_header_length: float = 0.0
    fwd_packets_per_s: float = 0.0
    bwd_packets_per_s: float = 0.0
    min_packet_length: float = 0.0
    max_packet_length: float = 0.0
    packet_length_mean: float = 0.0
    packet_length_std: float = 0.0
    packet_length_variance: float = 0.0
    fin_flag_count: float = 0.0
    syn_flag_count: float = 0.0
    rst_flag_count: float = 0.0
    psh_flag_count: float = 0.0
    ack_flag_count: float = 0.0
    urg_flag_count: float = 0.0
    cwe_flag_count: float = 0.0
    ece_flag_count: float = 0.0
    down_up_ratio: float = 0.0
    average_packet_size: float = 0.0
    avg_fwd_segment_size: float = 0.0
    avg_bwd_segment_size: float = 0.0
    fwd_header_length_1: float = 0.0
    fwd_avg_bytes_per_bulk: float = 0.0
    fwd_avg_packets_per_bulk: float = 0.0
    fwd_avg_bulk_rate: float = 0.0
    bwd_avg_bytes_per_bulk: float = 0.0
    bwd_avg_packets_per_bulk: float = 0.0
    bwd_avg_bulk_rate: float = 0.0
    subflow_fwd_packets: float = 0.0
    subflow_fwd_bytes: float = 0.0
    subflow_bwd_packets: float = 0.0
    subflow_bwd_bytes: float = 0.0
    init_win_bytes_forward: float = 0.0
    init_win_bytes_backward: float = 0.0
    act_data_pkt_fwd: float = 0.0
    min_seg_size_forward: float = 0.0
    active_mean: float = 0.0
    active_std: float = 0.0
    active_max: float = 0.0
    active_min: float = 0.0
    idle_mean: float = 0.0
    idle_std: float = 0.0
    idle_max: float = 0.0
    idle_min: float = 0.0

# Ordered list of JSON field names matching the 78 canonical features
FEATURE_ORDER = [
    "destination_port", "flow_duration",
    "total_fwd_packets", "total_backward_packets",
    "total_length_of_fwd_packets", "total_length_of_bwd_packets",
    "fwd_packet_length_max", "fwd_packet_length_min",
    "fwd_packet_length_mean", "fwd_packet_length_std",
    "bwd_packet_length_max", "bwd_packet_length_min",
    "bwd_packet_length_mean", "bwd_packet_length_std",
    "flow_bytes_per_s", "flow_packets_per_s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_length", "bwd_header_length",
    "fwd_packets_per_s", "bwd_packets_per_s",
    "min_packet_length", "max_packet_length",
    "packet_length_mean", "packet_length_std", "packet_length_variance",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count", "urg_flag_count",
    "cwe_flag_count", "ece_flag_count",
    "down_up_ratio", "average_packet_size",
    "avg_fwd_segment_size", "avg_bwd_segment_size",
    "fwd_header_length_1",
    "fwd_avg_bytes_per_bulk", "fwd_avg_packets_per_bulk", "fwd_avg_bulk_rate",
    "bwd_avg_bytes_per_bulk", "bwd_avg_packets_per_bulk", "bwd_avg_bulk_rate",
    "subflow_fwd_packets", "subflow_fwd_bytes",
    "subflow_bwd_packets", "subflow_bwd_bytes",
    "init_win_bytes_forward", "init_win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
]

CLASSES = ['BENIGN', 'ATTACK']

class PredictionResponse(BaseModel):
    malicious: bool
    prediction: str
    confidence: float

@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": True, "scaler_loaded": scaler is not None,
            "classes": CLASSES, "feature_count": len(FEATURE_ORDER)}

@app.post("/predict", response_model=PredictionResponse)
async def predict(features: FlowFeatures):
    try:
        fd = features.model_dump()
        arr = [fd.get(key, 0.0) for key in FEATURE_ORDER]
        # Sanitize
        arr = [0.0 if not np.isfinite(v) else v for v in arr]

        X = np.array([arr], dtype=np.float64)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        # Scale using the trained StandardScaler (or fallback)
        if scaler is not None:
            X_scaled = scaler.transform(X)
        else:
            # Fallback log-scale if scaler not available
            X_scaled = np.log1p(np.abs(X)) * np.sign(X)

        # TensorFlow Inference
        proba = model.predict(X_scaled, verbose=0)[0]
        class_idx = int(np.argmax(proba))
        conf = float(proba[class_idx])

        # Index 0 = BENIGN, Index 1 = ATTACK
        is_malicious = (class_idx != 0)
        pred_label = "ATTACK" if is_malicious else "BENIGN"

        return PredictionResponse(malicious=is_malicious, prediction=pred_label, confidence=round(conf, 4))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    print(f"\n{'='*50}")
    print(f"  IDPS ML Inference Service v2.0")
    print(f"  Port: {PORT} | Scaler: {'YES' if scaler else 'FALLBACK'}")
    print(f"  Classes: {CLASSES} | Features: {len(FEATURE_ORDER)}")
    print(f"{'='*50}\n")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
