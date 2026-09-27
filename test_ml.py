import requests
import json
import time

def test_ml_server():
    print("Testing ML Server (http://localhost:5001)...")
    
    # 1. Health check
    try:
        resp = requests.get("http://localhost:5001/health")
        print(f"Health Check: {resp.status_code} - {resp.json()}")
    except Exception as e:
        print(f"Failed to connect to ML server: {e}")
        return

    # 2. Test Benign Payload (all zeros / small numbers)
    benign_payload = {
        "destination_port": 80,
        "flow_duration": 1500.0,
        "total_fwd_packets": 2.0,
        "total_backward_packets": 2.0,
        "flow_bytes_per_s": 100.0
    }
    
    # 3. Test Attack Payload (something highly anomalous)
    attack_payload = {
        "destination_port": 445,
        "flow_duration": 100.0,
        "total_fwd_packets": 50000.0,
        "total_backward_packets": 0.0,
        "flow_bytes_per_s": 99999999.0,
        "syn_flag_count": 50000.0
    }
    
    try:
        t0 = time.time()
        b_resp = requests.post("http://localhost:5001/predict", json=benign_payload)
        t1 = time.time()
        print(f"\nBenign Payload Prediction (took {int((t1-t0)*1000)}ms):")
        print(json.dumps(b_resp.json(), indent=2))
        
        t0 = time.time()
        a_resp = requests.post("http://localhost:5001/predict", json=attack_payload)
        t1 = time.time()
        print(f"\nAttack Payload Prediction (took {int((t1-t0)*1000)}ms):")
        print(json.dumps(a_resp.json(), indent=2))
        
    except Exception as e:
        print(f"Prediction failed: {e}")

if __name__ == "__main__":
    test_ml_server()
