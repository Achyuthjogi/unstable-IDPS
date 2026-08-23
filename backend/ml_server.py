#!/usr/bin/env python3
"""
IDPS ML Inference Microservice
Loads the trained Random Forest model and serves predictions via FastAPI on port 5001.
"""
import os, sys, warnings
import numpy as np
warnings.filterwarnings("ignore", category=UserWarning)

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib

MODEL_PATH = os.environ.get("ML_MODEL_PATH", os.path.join(os.path.dirname(__file__), "..", "idps_ml_model.pkl"))
PORT = int(os.environ.get("ML_SERVICE_PORT", "5001"))

print(f"Loading ML model from: {MODEL_PATH}")
try:
    model = joblib.load(MODEL_PATH)
    FEATURE_NAMES = list(model.feature_names_in_)
    CLASSES = list(model.classes_)
    print(f"Model loaded! Features: {len(FEATURE_NAMES)}, Classes: {CLASSES}")
except Exception as e:
    print(f"FATAL: Failed to load ML model: {e}", file=sys.stderr)
    sys.exit(1)

app = FastAPI(title="IDPS ML Inference Service", version="1.0.0")

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

# Maps clean JSON keys to original CSV column names (with their leading spaces)
FIELD_TO_COLUMN = {
    "destination_port": " Destination Port", "flow_duration": " Flow Duration",
    "total_fwd_packets": " Total Fwd Packets", "total_backward_packets": " Total Backward Packets",
    "total_length_of_fwd_packets": "Total Length of Fwd Packets", "total_length_of_bwd_packets": " Total Length of Bwd Packets",
    "fwd_packet_length_max": " Fwd Packet Length Max", "fwd_packet_length_min": " Fwd Packet Length Min",
    "fwd_packet_length_mean": " Fwd Packet Length Mean", "fwd_packet_length_std": " Fwd Packet Length Std",
    "bwd_packet_length_max": "Bwd Packet Length Max", "bwd_packet_length_min": " Bwd Packet Length Min",
    "bwd_packet_length_mean": " Bwd Packet Length Mean", "bwd_packet_length_std": " Bwd Packet Length Std",
    "flow_bytes_per_s": "Flow Bytes/s", "flow_packets_per_s": " Flow Packets/s",
    "flow_iat_mean": " Flow IAT Mean", "flow_iat_std": " Flow IAT Std",
    "flow_iat_max": " Flow IAT Max", "flow_iat_min": " Flow IAT Min",
    "fwd_iat_total": "Fwd IAT Total", "fwd_iat_mean": " Fwd IAT Mean",
    "fwd_iat_std": " Fwd IAT Std", "fwd_iat_max": " Fwd IAT Max", "fwd_iat_min": " Fwd IAT Min",
    "bwd_iat_total": "Bwd IAT Total", "bwd_iat_mean": " Bwd IAT Mean",
    "bwd_iat_std": " Bwd IAT Std", "bwd_iat_max": " Bwd IAT Max", "bwd_iat_min": " Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags", "bwd_psh_flags": " Bwd PSH Flags",
    "fwd_urg_flags": " Fwd URG Flags", "bwd_urg_flags": " Bwd URG Flags",
    "fwd_header_length": " Fwd Header Length", "bwd_header_length": " Bwd Header Length",
    "fwd_packets_per_s": "Fwd Packets/s", "bwd_packets_per_s": " Bwd Packets/s",
    "min_packet_length": " Min Packet Length", "max_packet_length": " Max Packet Length",
    "packet_length_mean": " Packet Length Mean", "packet_length_std": " Packet Length Std",
    "packet_length_variance": " Packet Length Variance",
    "fin_flag_count": "FIN Flag Count", "syn_flag_count": " SYN Flag Count",
    "rst_flag_count": " RST Flag Count", "psh_flag_count": " PSH Flag Count",
    "ack_flag_count": " ACK Flag Count", "urg_flag_count": " URG Flag Count",
    "cwe_flag_count": " CWE Flag Count", "ece_flag_count": " ECE Flag Count",
    "down_up_ratio": " Down/Up Ratio", "average_packet_size": " Average Packet Size",
    "avg_fwd_segment_size": " Avg Fwd Segment Size", "avg_bwd_segment_size": " Avg Bwd Segment Size",
    "fwd_header_length_1": " Fwd Header Length.1",
    "fwd_avg_bytes_per_bulk": "Fwd Avg Bytes/Bulk", "fwd_avg_packets_per_bulk": " Fwd Avg Packets/Bulk",
    "fwd_avg_bulk_rate": " Fwd Avg Bulk Rate", "bwd_avg_bytes_per_bulk": " Bwd Avg Bytes/Bulk",
    "bwd_avg_packets_per_bulk": " Bwd Avg Packets/Bulk", "bwd_avg_bulk_rate": "Bwd Avg Bulk Rate",
    "subflow_fwd_packets": "Subflow Fwd Packets", "subflow_fwd_bytes": " Subflow Fwd Bytes",
    "subflow_bwd_packets": " Subflow Bwd Packets", "subflow_bwd_bytes": " Subflow Bwd Bytes",
    "init_win_bytes_forward": "Init_Win_bytes_forward", "init_win_bytes_backward": " Init_Win_bytes_backward",
    "act_data_pkt_fwd": " act_data_pkt_fwd", "min_seg_size_forward": " min_seg_size_forward",
    "active_mean": "Active Mean", "active_std": " Active Std",
    "active_max": " Active Max", "active_min": " Active Min",
    "idle_mean": "Idle Mean", "idle_std": " Idle Std",
    "idle_max": " Idle Max", "idle_min": " Idle Min",
}

# Build reverse lookup: CSV column name -> JSON field name
COLUMN_TO_FIELD = {v: k for k, v in FIELD_TO_COLUMN.items()}

class PredictionResponse(BaseModel):
    malicious: bool
    prediction: str
    confidence: float

@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": True, "classes": CLASSES, "feature_count": len(FEATURE_NAMES)}

@app.post("/predict", response_model=PredictionResponse)
async def predict(features: FlowFeatures):
    try:
        fd = features.model_dump()
        arr = []
        for col_name in FEATURE_NAMES:
            json_key = COLUMN_TO_FIELD.get(col_name, "")
            val = fd.get(json_key, 0.0) if json_key else 0.0
            if not np.isfinite(val):
                val = 0.0
            arr.append(val)

        X = np.array([arr], dtype=np.float64)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        pred = model.predict(X)[0]
        proba = model.predict_proba(X)[0]
        class_idx = list(model.classes_).index(pred)
        conf = float(proba[class_idx])

        return PredictionResponse(malicious=(pred != "BENIGN"), prediction=str(pred), confidence=round(conf, 4))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    print(f"\n{'='*50}")
    print(f"  IDPS ML Inference Service")
    print(f"  Port: {PORT} | Classes: {CLASSES} | Features: {len(FEATURE_NAMES)}")
    print(f"{'='*50}\n")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
