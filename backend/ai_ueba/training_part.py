'''

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# --- LOAD DATA ---
df = pd.read_csv("synthetic_extension_events.csv")

# --- FEATURE ENGINEERING (aggregate by session) ---
session_df = df.groupby("session_id").agg({
    "user_hash": "first",
    "session_duration_ms": "max",
    "num_events_in_session": "max",
    "error_flag": "sum",
    "duration_since_last_event_ms": "mean",
    "label_uninstall_7d": "max",
    "anomaly_flag": "max"
}).reset_index()

# Count event types per session
event_counts = df.pivot_table(
    index="session_id",
    columns="event_type",
    aggfunc="size",
    fill_value=0
).reset_index()

session_df = session_df.merge(event_counts, on="session_id", how="left")

# Add derived features
session_df["error_rate"] = session_df["error_flag"] / session_df["num_events_in_session"]
session_df["events_per_sec"] = session_df["num_events_in_session"] / (session_df["session_duration_ms"] / 1000)
session_df["avg_event_gap"] = session_df["duration_since_last_event_ms"]

# Fill possible NaNs
session_df.fillna(0, inplace=True)

# --- FEATURE MATRIX (ALL FEATURES for both models) ---
feature_cols = [c for c in session_df.columns if c not in ["session_id", "user_hash", "label_uninstall_7d", "anomaly_flag"]]
X = session_df[feature_cols]

# --- 1️⃣  ANOMALY DETECTION (Isolation Forest) ---
print("=== Anomaly Detection ===")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

iso = IsolationForest(contamination=0.1, random_state=42)
iso_preds = iso.fit_predict(X_scaled)
iso_preds = np.where(iso_preds == -1, 1, 0)  # Convert to 1/0

print("Predicted anomalies:", np.sum(iso_preds))
print("Real anomalies:", session_df["anomaly_flag"].sum())
print(classification_report(session_df["anomaly_flag"], iso_preds))

# --- 2️⃣  SUPERVISED MODEL: Predict uninstall_7d ---
print("\n=== Uninstall Prediction ===")
y = session_df["label_uninstall_7d"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)
y_pred = rf.predict(X_test)
y_proba = rf.predict_proba(X_test)[:, 1]

print(classification_report(y_test, y_pred))
print("ROC AUC:", roc_auc_score(y_test, y_proba))

# --- Confusion Matrix ---
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(5,4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.show()

# --- Feature Importance Chart ---
importances = pd.Series(rf.feature_importances_, index=X_train.columns).sort_values(ascending=False)
plt.figure(figsize=(8,5))
importances.head(10).plot(kind="barh")
plt.title("Top 10 Feature Importances")
plt.gca().invert_yaxis()
plt.show()

joblib.dump(rf, "uninstall_predictor.pkl")
joblib.dump(iso, "isolation_forest_model.pkl")
print("✅ Models saved as uninstall_predictor.pkl and isolation_forest_model.pkl")

'''
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# --- LOAD DATA ---
df = pd.read_csv("synthetic_extension_events.csv")  # your new synthetic dataset
print(f"✅ Loaded {len(df)} rows")

# --- FEATURE ENGINEERING (aggregate by session) ---
session_df = df.groupby("session_id").agg({
    "user_id": "first",
    "domain": pd.Series.nunique,           # number of unique domains visited
    "event_type": pd.Series.nunique,       # number of unique event types
    "suspicious_flag": "sum",              # total suspicious events
    "time_on_page": ["mean", "sum", "max"],# browsing time features
    "browser": "first",
    "os": "first",
    "locale": "first",
    "label": "max"                         # 1 = attack/malicious, 0 = normal
}).reset_index()

# Flatten MultiIndex columns
session_df.columns = ['_'.join(c).strip('_') for c in session_df.columns.values]

# Rename for clarity
session_df.rename(columns={
    "domain_nunique": "unique_domains",
    "event_type_nunique": "unique_event_types",
    "suspicious_flag_sum": "suspicious_count",
    "time_on_page_mean": "avg_time_on_page",
    "time_on_page_sum": "total_time_on_page",
    "time_on_page_max": "max_time_on_page",
    "label_max": "label"
}, inplace=True)

# --- Encode categorical features ---
session_df = pd.get_dummies(session_df, columns=["browser_first", "os_first", "locale_first"], drop_first=True)

# --- FEATURE MATRIX ---
features = [c for c in session_df.columns if c not in ["session_id", "user_id_first", "label"]]
X = session_df[features]

# --- SAVE FEATURE COLUMNS for later use ---
joblib.dump(features, "ueba_feature_cols.pkl")  # ✅ Save columns for new session predictions

# --- STANDARDIZE ---
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, "ueba_scaler.pkl")

# --- ANOMALY DETECTION (Isolation Forest) ---
iso = IsolationForest(
    n_estimators=200,
    contamination=0.05,  # assume ~5% anomalies
    random_state=42
)
iso.fit(X_scaled)

# Predict anomaly scores
session_df["anomaly_score"] = iso.decision_function(X_scaled)
session_df["anomaly_flag"] = (iso.predict(X_scaled) == -1).astype(int)

joblib.dump(iso, "ueba_isolation_forest.pkl")

# --- SAVE RESULTS ---
session_df.to_csv("ueba_sessions.csv", index=False)
print(f"📁 Saved ueba_sessions.csv with {len(session_df)} sessions")

# --- VISUALIZE DISTRIBUTION ---
plt.figure(figsize=(6,4))
sns.histplot(session_df["anomaly_score"], bins=30, kde=True)
plt.title("Anomaly Score Distribution")
plt.xlabel("Anomaly Score"); plt.ylabel("Frequency")
plt.tight_layout()
plt.show()

# --- Display Most Suspicious Sessions ---
top_anomalies = session_df.sort_values("anomaly_score").head(10)
print("\n🚨 Top 10 Suspicious Sessions:")
print(top_anomalies[["session_id", "user_id_first", "suspicious_count", "unique_domains",
                     "unique_event_types", "avg_time_on_page", "anomaly_score", "anomaly_flag"]])

print("\n✅ UEBA anomaly detection complete.")
