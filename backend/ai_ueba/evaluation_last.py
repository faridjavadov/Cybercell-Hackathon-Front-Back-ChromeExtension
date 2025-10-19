# step 4 — evaluation and feature contribution analysis
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


INPUT_SESSION_CSV = "ueba_sessions.csv"
SURROGATE_MODEL_NAME = "surrogate_rf_for_anomaly.pkl"


def run_evaluation():
    # we load processed sessions generated in previous steps
    sdf = pd.read_csv(INPUT_SESSION_CSV)
    print("loaded sessions:", sdf.shape)

    assert "anomaly_score" in sdf.columns and "anomaly_flag" in sdf.columns, "run isolation forest step first."

    # we compare anomaly predictions with ground truth if label exists
    if "label" in sdf.columns:
        y_true = sdf["label"].astype(int).values
        y_pred = sdf["anomaly_flag"].astype(int).values

        print("\n--- classification report (anomaly_flag vs label) ---")
        print(classification_report(y_true, y_pred, digits=4))

        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(5, 4))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
        plt.title("Confusion Matrix: anomaly_flag vs label")
        plt.xlabel("Predicted")
        plt.ylabel("True")
        plt.tight_layout()
        plt.savefig("eval_confusion_matrix.png")

        if sdf["label"].nunique() > 1:
            fpr, tpr, _ = roc_curve(y_true, sdf["anomaly_score"])
            roc_auc = auc(fpr, tpr)
            plt.figure(figsize=(6, 4))
            plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.3f}")
            plt.plot([0, 1], [0, 1], linestyle="--", color="gray")
            plt.title("ROC Curve (anomaly_score)")
            plt.xlabel("FPR")
            plt.ylabel("TPR")
            plt.legend()
            plt.tight_layout()
            plt.savefig("eval_roc_curve.png")

            precision, recall, _ = precision_recall_curve(y_true, -sdf["anomaly_score"])
            ap = average_precision_score(y_true, -sdf["anomaly_score"])
            plt.figure(figsize=(6, 4))
            plt.plot(recall, precision, label=f"AP = {ap:.3f}")
            plt.xlabel("Recall")
            plt.ylabel("Precision")
            plt.title("Precision-Recall Curve")
            plt.legend()
            plt.tight_layout()
            plt.savefig("eval_pr_curve.png")
    else:
        print("no 'label' column found — skipping supervised evaluation.")

    # we compute feature correlations to anomaly score
    exclude = {"session_id", "user_id", "anomaly_flag", "label", "anomaly_score"}
    numeric_cols = [
        c for c in sdf.columns
        if (sdf[c].dtype in [np.float64, np.int64]) and c not in exclude
    ]

    corrs = {}
    for c in numeric_cols:
        corrs[c] = sdf[c].corr(sdf["anomaly_score"], method="spearman")

    corr_df = pd.DataFrame.from_dict(corrs, orient="index", columns=["spearman_with_anomaly_score"])
    corr_df["abs_corr"] = corr_df["spearman_with_anomaly_score"].abs()
    corr_df = corr_df.sort_values("abs_corr", ascending=False)
    corr_df.to_csv("feature_correlation_with_anomaly_score.csv")

    plt.figure(figsize=(8, 6))
    sns.barplot(
        x="spearman_with_anomaly_score",
        y=corr_df.head(12).index,
        data=corr_df.head(12)
    )
    plt.title("Top features by Spearman correlation with anomaly_score")
    plt.tight_layout()
    plt.savefig("top_feature_correlations.png")

    # we train a surrogate random forest to interpret anomaly_flag decisions
    X_sur = sdf[numeric_cols].fillna(0).values
    y_sur = sdf["anomaly_flag"].astype(int).values

    rf = RandomForestClassifier(n_estimators=200, random_state=42)
    rf.fit(X_sur, y_sur)
    joblib.dump(rf, SURROGATE_MODEL_NAME)

    importances = pd.Series(rf.feature_importances_, index=numeric_cols).sort_values(ascending=False)
    importances.head(30).to_csv("surrogate_feature_importances.csv")

    plt.figure(figsize=(8, 6))
    importances.head(20).plot(kind="barh")
    plt.gca().invert_yaxis()
    plt.title("Surrogate RF feature importances")
    plt.tight_layout()
    plt.savefig("surrogate_feature_importances.png")

    # we use permutation importance for robustness
    perm = permutation_importance(rf, X_sur, y_sur, n_repeats=10, random_state=42, n_jobs=1)
    perm_importances = pd.Series(perm.importances_mean, index=numeric_cols).sort_values(ascending=False)
    perm_importances.head(20).to_csv("permutation_importances.csv")

    plt.figure(figsize=(8, 6))
    perm_importances.head(20).plot(kind="barh")
    plt.gca().invert_yaxis()
    plt.title("Permutation importances (surrogate RF)")
    plt.tight_layout()
    plt.savefig("permutation_importances.png")

    # we preview a few top anomalous sessions for manual inspection
    top_sessions = sdf.sort_values("anomaly_score").head(10)
    cols_to_show = ["session_id", "user_id", "anomaly_score", "anomaly_flag", "label"] + numeric_cols[:8]
    print("\nTop anomalous sessions sample:")
    print(top_sessions[cols_to_show].to_string(index=False))


if __name__ == "__main__":
    run_evaluation()
    print("evaluation and feature contribution analysis done.")
