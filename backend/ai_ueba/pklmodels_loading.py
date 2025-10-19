import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib

def train_simple_isolation_forest():
    # we load generated synthetic dataset
    df = pd.read_csv("synthetic_extension_events.csv")

    # we aggregate raw events into session-level metrics
    session_df = df.groupby("session_id").agg({
        "time_on_page": "sum",
        "event_type": "count",
        "suspicious_flag": "sum"
    }).reset_index()

    # we derive basic behavioral ratios for anomaly detection
    session_df["events_per_sec"] = session_df["event_type"] / session_df["time_on_page"]
    session_df["suspicious_rate"] = session_df["suspicious_flag"] / session_df["event_type"]

    feature_cols = ["time_on_page", "event_type", "events_per_sec", "suspicious_rate"]
    X = session_df[feature_cols].fillna(0)

    # we standardize data so isolation forest handles feature scales fairly
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # we train isolation forest to detect unusual sessions
    iso = IsolationForest(contamination=0.1, random_state=42)
    iso.fit(X_scaled)

    # we save the trained model and scaler
    joblib.dump(iso, "isolation_forest_model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    print("model and scaler saved")


if __name__ == "__main__":
    train_simple_isolation_forest()
