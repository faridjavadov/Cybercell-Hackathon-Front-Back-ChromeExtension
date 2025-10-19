import pandas as pd
import joblib
import json
from datetime import datetime

rf = joblib.load("uninstall_predictor.pkl")
iso = joblib.load("isolation_forest_model.pkl")
with open("feature_columns.json", "r") as f:
    feature_cols = json.load(f)

# --- Example logs from extension ---
logs = [
    {"id": 742, "url": "...", "timestamp": "2025-10-19T06:40:12.946000", "type": "normal", "reason": "Page navigation"},
    {"id": 741, "url": "...", "timestamp": "2025-10-19T06:40:05.522000", "type": "suspicious", "reason": "js_evasion: obfuscation"},
    {"id": 740, "url": "...", "timestamp": "2025-10-19T06:40:05.521000", "type": "suspicious", "reason": "js_evasion: obfuscation"},
    {"id": 738, "url": "...", "timestamp": "2025-10-19T06:40:04.007000", "type": "normal", "reason": "Page navigation"},
    {"id": 737, "url": "...", "timestamp": "2025-10-19T06:40:02.727000", "type": "normal", "reason": "Extension active"}
]

df = pd.DataFrame(logs)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values("timestamp")

# --- Aggregate numeric features ---
session_duration_ms = (df["timestamp"].max() - df["timestamp"].min()).total_seconds() * 1000
num_events = len(df)
error_rate = (df["type"] == "suspicious").sum() / num_events
avg_event_gap = df["timestamp"].diff().dt.total_seconds().fillna(0).mean() * 1000
events_per_sec = num_events / (session_duration_ms / 1000)

click_count = (df["reason"] == "Page navigation").sum()
js_evasion_count = df["reason"].str.contains("js_evasion").sum()
# Add more counts if needed, e.g., api_call, permission_prompt, etc.
event_counts = {
    "click": click_count,
    "js_evasion": js_evasion_count
}

# --- Combine features ---
features = {
    "session_duration_ms": session_duration_ms,
    "num_events_in_session": num_events,
    "error_rate": error_rate,
    "avg_event_gap": avg_event_gap,
    "events_per_sec": events_per_sec,
}
features.update(event_counts)

X_new = pd.DataFrame([features])

for col in feature_cols:
    if col not in X_new.columns:
        X_new[col] = 0
X_new = X_new[feature_cols]

# --- Make predictions ---
anomaly_flag = iso.predict(X_new)[0]
anomaly_flag = 1 if anomaly_flag == -1 else 0

predicted_uninstall = int(rf.predict(X_new)[0])
uninstall_prob = float(rf.predict_proba(X_new)[:,1][0])

# --- Return results ---
result = {
    "anomaly_flag": anomaly_flag,
    "predicted_uninstall": predicted_uninstall,
    "uninstall_prob": uninstall_prob
}

print(json.dumps(result, indent=2))
