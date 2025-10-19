import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib


def train_and_evaluate_models():
    # we load session-based dataset
    df = pd.read_csv("synthetic_extension_events.csv")

    # we aggregate raw events into session-level features
    session_df = df.groupby("session_id").agg({
        "user_hash": "first",
        "session_duration_ms": "max",
        "num_events_in_session": "max",
        "error_flag": "sum",
        "duration_since_last_event_ms": "mean",
        "label_uninstall_7d": "max",
        "anomaly_flag": "max"
    }).reset_index()

    # we count types of events in each session
    event_counts = df.pivot_table(
        index="session_id",
        columns="event_type",
        aggfunc="size",
        fill_value=0
    ).reset_index()
    session_df = session_df.merge(event_counts, on="session_id", how="left")

    # we create basic behavioral ratios
    session_df["error_rate"] = session_df["error_flag"] / session_df["num_events_in_session"]
    session_df["events_per_sec"] = session_df["num_events_in_session"] / (
        session_df["session_duration_ms"] / 1000
    )
    session_df["avg_event_gap"] = session_df["duration_since_last_event_ms"]
    session_df.fillna(0, inplace=True)

    # we select usable features
    feature_cols = [
        c for c in session_df.columns
        if c not in ["session_id", "user_hash", "label_uninstall_7d", "anomaly_flag"]
    ]
    X = session_df[feature_cols]

    # we normalize data for isolation forest
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(contamination=0.1, random_state=42)
    iso_preds = iso.fit_predict(X_scaled)
    iso_preds = np.where(iso_preds == -1, 1, 0)

    # we evaluate anomaly detection against ground truth
    print("=== Anomaly Detection ===")
    print(classification_report(session_df["anomaly_flag"], iso_preds))

    # we train random forest to predict uninstall behavior
    y = session_df["label_uninstall_7d"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    y_proba = rf.predict_proba(X_test)[:, 1]

    print("\n=== Uninstall Prediction ===")
    print(classification_report(y_test, y_pred))
    print("ROC AUC:", roc_auc_score(y_test, y_proba))

    # we visualize confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.show()

    # we show top feature importances
    importances = pd.Series(rf.feature_importances_, index=X_train.columns).sort_values(ascending=False)
    plt.figure(figsize=(8, 5))
    importances.head(10).plot(kind="barh")
    plt.title("Top 10 Feature Importances")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.show()

    # we save both models
    joblib.dump(rf, "uninstall_predictor.pkl")
    joblib.dump(iso, "isolation_forest_model.pkl")


def run_ueba_anomaly_detection():
    # we load same synthetic dataset but create different feature logic for ueba
    df = pd.read_csv("synthetic_extension_events.csv")

    session_df = df.groupby("session_id").agg({
        "user_id": "first",
        "domain": pd.Series.nunique,
        "event_type": pd.Series.nunique,
        "suspicious_flag": "sum",
        "time_on_page": ["mean", "sum", "max"],
        "browser": "first",
        "os": "first",
        "locale": "first",
        "label": "max"
    }).reset_index()

    session_df.columns = ['_'.join(c).strip('_') for c in session_df.columns.values]
    session_df.rename(columns={
        "domain_nunique": "unique_domains",
        "event_type_nunique": "unique_event_types",
        "suspicious_flag_sum": "suspicious_count",
        "time_on_page_mean": "avg_time_on_page",
        "time_on_page_sum": "total_time_on_page",
        "time_on_page_max": "max_time_on_page",
        "label_max": "label"
    }, inplace=True)

    # we encode categorical columns to use them in isolation forest
    session_df = pd.get_dummies(
        session_df,
        columns=["browser_first", "os_first", "locale_first"],
        drop_first=True
    )

    features = [c for c in session_df.columns if c not in ["session_id", "user_id_first", "label"]]
    X = session_df[features]
    joblib.dump(features, "ueba_feature_cols.pkl")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, "ueba_scaler.pkl")

    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    iso.fit(X_scaled)

    session_df["anomaly_score"] = iso.decision_function(X_scaled)
    session_df["anomaly_flag"] = (iso.predict(X_scaled) == -1).astype(int)
    joblib.dump(iso, "ueba_isolation_forest.pkl")

    session_df.to_csv("ueba_sessions.csv", index=False)

    # we show how anomaly scores are distributed
    plt.figure(figsize=(6, 4))
    sns.histplot(session_df["anomaly_score"], bins=30, kde=True)
    plt.title("Anomaly Score Distribution")
    plt.xlabel("Anomaly Score")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.show()

    # we display highest-risk sessions
    top_anomalies = session_df.sort_values("anomaly_score").head(10)
    print("\nTop Suspicious Sessions:")
    print(top_anomalies[[
        "session_id", "user_id_first", "suspicious_count",
        "unique_domains", "unique_event_types",
        "avg_time_on_page", "anomaly_score", "anomaly_flag"
    ]])


if __name__ == "__main__":
    # we run both model training and ueba detection
    train_and_evaluate_models()
    run_ueba_anomaly_detection()
