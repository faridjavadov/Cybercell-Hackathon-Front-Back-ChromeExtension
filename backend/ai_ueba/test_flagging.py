import pandas as pd
import numpy as np
import joblib
import hashlib
import random
import json
from sklearn.preprocessing import StandardScaler

# --- Load trained model and scaler ---
iso = joblib.load("ueba_isolation_forest.pkl")
scaler = joblib.load("ueba_scaler.pkl")
feature_cols = joblib.load("ueba_feature_cols.pkl")  # feature order during training

# --- Helper function to generate user_id hash ---
def hash_id(value):
    return hashlib.sha256(value.encode()).hexdigest()[:16]

# --- Aggregate session features ---
def aggregate_session_features(events):
    """
    events: list of dicts, each dict with keys:
      - event_type
      - time_on_page
      - suspicious_flag
      - browser
      - os
      - locale
    """
    df = pd.DataFrame(events)
    feature = {}

    # Numeric features
    feature["unique_domains"] = df["domain"].nunique() if "domain" in df.columns else 1
    feature["unique_event_types"] = df["event_type"].nunique()
    feature["suspicious_count"] = df["suspicious_flag"].sum() if "suspicious_flag" in df.columns else 0
    feature["avg_time_on_page"] = df["time_on_page"].mean() if "time_on_page" in df.columns else 0
    feature["total_time_on_page"] = df["time_on_page"].sum() if "time_on_page" in df.columns else 0
    feature["max_time_on_page"] = df["time_on_page"].max() if "time_on_page" in df.columns else 0

    # Categorical one-hot encoding
    for col, values in [("browser", ["Chrome","Edge","Firefox","Safari"]),
                        ("os", ["Windows","Linux","macOS"]),
                        ("locale", ["en-US","en-GB","tr-TR","az-AZ","ru-RU"])]:
        val = df[col].iloc[0] if col in df.columns else values[0]
        for v in values[1:]:  # drop_first
            feature[f"{col}_{v}"] = 1 if val == v else 0

    # Ensure order and missing features
    for c in feature_cols:
        if c not in feature:
            feature[c] = 0

    return pd.DataFrame([feature])[feature_cols]

# --- Simulate new session from extension logs ---
def process_new_session(events, session_id=None, user_id=None):
    """
    events: list of dicts coming from extension
    """
    if user_id is None:
        user_id = hash_id(f"user_{random.randint(1,1000)}")
    if session_id is None:
        session_id = f"session_{random.randint(1000,9999)}"

    # Aggregate features
    X_new = aggregate_session_features(events)

    # Scale features
    X_scaled = scaler.transform(X_new)

    # Predict anomaly
    anomaly_flag = iso.predict(X_scaled)[0]
    anomaly_flag = 1 if anomaly_flag == -1 else 0
    anomaly_score = iso.decision_function(X_scaled)[0]

    # Build output JSON (example 5-10 attributes)
    output = {
        "session_id": session_id,
        "user_id": user_id,
        "anomaly_flag": int(anomaly_flag),
        "anomaly_score": float(anomaly_score),
        "unique_domains": int(X_new["unique_domains"].values[0]),
        "unique_event_types": int(X_new["unique_event_types"].values[0]),
        "suspicious_count": int(X_new["suspicious_count"].values[0]),
        "avg_time_on_page": float(X_new["avg_time_on_page"].values[0]),
        "total_time_on_page": float(X_new["total_time_on_page"].values[0]),
        "max_time_on_page": float(X_new["max_time_on_page"].values[0])
    }

    return json.dumps(output, indent=2)

# --- Example usage ---
if __name__ == "__main__":
    # Example new session events from extension
    new_events = [
        {"event_type":"click","domain":"google.com","time_on_page":5,"suspicious_flag":0,
         "browser":"Chrome","os":"Windows","locale":"en-US"},
        {"event_type":"page_open","domain":"youtube.com","time_on_page":10,"suspicious_flag":0,
         "browser":"Chrome","os":"Windows","locale":"en-US"},
        {"event_type":"api_call","domain":"phishing-site.xyz","time_on_page":2,"suspicious_flag":1,
         "browser":"Chrome","os":"Windows","locale":"en-US"}
    ]

    result = process_new_session(new_events)

    # Save JSON to file for backend
    with open("session_output.json", "w") as f:
        json.dump(result, f, indent=2)

    print("✅ JSON saved to session_output.json")
    print(json.dumps(result, indent=2))