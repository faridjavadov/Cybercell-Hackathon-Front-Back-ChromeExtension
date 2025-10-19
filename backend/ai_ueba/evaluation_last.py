# Step 4 — Evaluation and Feature Contribution Analysis
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from sklearn.metrics import (
    confusion_matrix, classification_report,
    precision_recall_curve, roc_curve, auc, average_precision_score
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance

INPUT_SESSION_CSV = "ueba_sessions.csv"   # file produced earlier
SURROGATE_MODEL_NAME = "surrogate_rf_for_anomaly.pkl"

# ----- Load sessions -----
sdf = pd.read_csv(INPUT_SESSION_CSV)
print("Loaded sessions:", sdf.shape)

# Ensure columns we need exist
assert "anomaly_score" in sdf.columns and "anomaly_flag" in sdf.columns, "Run isolation forest step first."

if "label" in sdf.columns:
    y_true = sdf["label"].astype(int).values
    y_pred = sdf["anomaly_flag"].astype(int).values

    print("\n--- Classification report (anomaly_flag vs label) ---")
    print(classification_report(y_true, y_pred, digits=4))

    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(5,4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.title("Confusion Matrix: anomaly_flag vs label")
    plt.xlabel("Predicted (anomaly_flag)"); plt.ylabel("True (label)")
    plt.tight_layout()
    plt.savefig("eval_confusion_matrix.png")
    print("Saved eval_confusion_matrix.png")

    # ROC & PR (use anomaly_score as continuous)
    if sdf["label"].nunique() > 1:
        fpr, tpr, _ = roc_curve(y_true, sdf["anomaly_score"])
        roc_auc = auc(fpr, tpr)
        plt.figure(figsize=(6,4))
        plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.3f}")
        plt.plot([0,1],[0,1], linestyle="--", color="gray")
        plt.title("ROC Curve (anomaly_score)")
        plt.xlabel("FPR"); plt.ylabel("TPR")
        plt.legend()
        plt.tight_layout()
        plt.savefig("eval_roc_curve.png")
        print("Saved eval_roc_curve.png")

        precision, recall, _ = precision_recall_curve(y_true, -sdf["anomaly_score"])  # note: higher negative score -> anomaly
        ap = average_precision_score(y_true, -sdf["anomaly_score"])
        plt.figure(figsize=(6,4))
        plt.plot(recall, precision, label=f"AP = {ap:.3f}")
        plt.xlabel("Recall"); plt.ylabel("Precision"); plt.title("Precision-Recall Curve")
        plt.legend()
        plt.tight_layout()
        plt.savefig("eval_pr_curve.png")
        print("Saved eval_pr_curve.png")
else:
    print("No true 'label' column found — skipping supervised evaluation.")

# ----- 2) Correlation with anomaly_score -----
# Select numeric feature columns (exclude identifiers and label/flags)
exclude = {"session_id", "user_id", "anomaly_flag", "label", "anomaly_score"}
numeric_cols = [c for c in sdf.columns if (sdf[c].dtype in [np.float64, np.int64]) and c not in exclude]
print("\nNumeric features used for correlation:", numeric_cols)

corrs = {}
for c in numeric_cols:
    # Spearman is robust to non-linear monotonic relations
    corr = sdf[c].corr(sdf["anomaly_score"], method="spearman")
    corrs[c] = corr

corr_df = pd.DataFrame.from_dict(corrs, orient="index", columns=["spearman_with_anomaly_score"])
corr_df["abs_corr"] = corr_df["spearman_with_anomaly_score"].abs()
corr_df = corr_df.sort_values("abs_corr", ascending=False)
corr_df.to_csv("feature_correlation_with_anomaly_score.csv")
print("Saved feature_correlation_with_anomaly_score.csv")
print("\nTop features by absolute Spearman correlation:")
print(corr_df.head(15))

# Plot top correlated features
topn = corr_df.head(12).index.tolist()
plt.figure(figsize=(8,6))
sns.barplot(x="spearman_with_anomaly_score", y=corr_df.head(12).index, data=corr_df.head(12))
plt.title("Top features by Spearman correlation with anomaly_score")
plt.tight_layout()
plt.savefig("top_feature_correlations.png")
print("Saved top_feature_correlations.png")

# ----- 3) Surrogate model for explanations (learn to predict anomaly_flag) -----
# Build feature matrix X_sur for surrogate model (use same numeric columns)
X_sur = sdf[numeric_cols].fillna(0).values
y_sur = sdf["anomaly_flag"].astype(int).values

rf = RandomForestClassifier(n_estimators=200, random_state=42)
rf.fit(X_sur, y_sur)
joblib.dump(rf, SURROGATE_MODEL_NAME)
print("Saved surrogate RandomForest:", SURROGATE_MODEL_NAME)

# Feature importances
importances = pd.Series(rf.feature_importances_, index=numeric_cols).sort_values(ascending=False)
importances.head(30).to_csv("surrogate_feature_importances.csv")
print("Saved surrogate_feature_importances.csv")
plt.figure(figsize=(8,6))
importances.head(20).plot(kind="barh")
plt.gca().invert_yaxis()
plt.title("Surrogate RF feature importances (predicting anomaly_flag)")
plt.tight_layout()
plt.savefig("surrogate_feature_importances.png")
print("Saved surrogate_feature_importances.png")

# ----- 4) Permutation importance (optional more robust) -----
print("\nComputing permutation importance (may take time)...")
perm = permutation_importance(rf, X_sur, y_sur, n_repeats=10, random_state=42, n_jobs=1)
perm_importances = pd.Series(perm.importances_mean, index=numeric_cols).sort_values(ascending=False)
perm_importances.head(20).to_csv("permutation_importances.csv")
plt.figure(figsize=(8,6))
perm_importances.head(20).plot(kind="barh")
plt.gca().invert_yaxis()
plt.title("Permutation importances (surrogate RF)")
plt.tight_layout()
plt.savefig("permutation_importances.png")
print("Saved permutation_importances.png")

# ----- 5) Example session explanations (show handful) -----
# show top 5 anomalous sessions and their key feature values
top_sessions = sdf.sort_values("anomaly_score").head(10)  # most anomalous (lowest score)
cols_to_show = ["session_id", "user_id", "anomaly_score", "anomaly_flag", "label"] + numeric_cols[:8]
print("\nTop anomalous sessions sample (partial features):")
print(top_sessions[cols_to_show].head(10).to_string(index=False))

print("\n✅ Evaluation & feature contribution analysis done.")
