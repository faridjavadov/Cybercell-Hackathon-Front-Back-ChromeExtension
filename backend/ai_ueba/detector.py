
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
from features import BehaviorFeatures  # Import our feature extractor
from user_profile import UserProfile   # Import user profile class


class SimpleUEBADetector:
    """
    User and Entity Behavior Analytics
    """

    def __init__(self):
        # Layer 1: Statistical (per-user baselines)
        self.user_profiles = {}  # {user_id: UserProfile}

        # Layer 2: ML model (global anomalies)
        self.global_model = IsolationForest(
            contamination=0.05,  # 5% of data is anomalous
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def process_events(self, user_id, events):
        """
        Main entry point: analyze user behavior
        """
        # 1. Extract features
        features = BehaviorFeatures.extract(events, user_id)
        if not features:
            return {'anomaly': False, 'score': 0}

        # 2. Get or create user profile
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserProfile(user_id)

        profile = self.user_profiles[user_id]

        personal_score = profile.get_anomaly_score(features)

        X = self._features_to_array(features)
        global_score = 0
        if self.is_trained:
            X_scaled = self.scaler.transform(X)
            # score_samples: higher = more normal → invert for anomaly score
            normal_score = self.global_model.score_samples(X_scaled)[0]
            global_score = -normal_score + 1  # shift so 1 ≈ normal baseline

        # 5. Combine scores
        final_score = (personal_score * 0.6) + (global_score * 0.4)

        # 6. Update profile with normal behavior
        if final_score < 2.0:  # Not anomalous
            profile.update(features)

        # 7. Determine if anomaly
        is_anomaly = final_score > 2.5

        return {
            'anomaly': is_anomaly,
            'score': float(final_score),
            'personal_score': float(personal_score),
            'global_score': float(global_score),
            'reason': self._explain(features, profile, final_score)
        }

    def train_global_model(self, training_data):
        """
        Train global model on historical normal behavior
        training_data: list of feature dicts
        """
        if not training_data:
            raise ValueError("training_data is empty")

        # Convert list of dicts -> 2-D array (n, d)
        X_list = [self._features_to_array(f).ravel() for f in training_data]
        X = np.vstack(X_list)  # ensures shape (n, d)

        # Fit scaler then IsolationForest
        X_scaled = self.scaler.fit_transform(X)
        self.global_model.fit(X_scaled)
        self.is_trained = True
        print(f"✅ Trained on {len(training_data)} samples with shape {X_scaled.shape}")

    def _features_to_array(self, features):
        """Convert feature dict to numpy array"""
        feature_order = [
            'session_duration_min', 'hour_of_day', 'is_weekend',
            'avg_typing_speed', 'typing_speed_std',
            'click_rate', 'copy_count', 'copy_rate',
            'unique_pages_visited', 'page_visit_rate'
        ]
        return np.array([[features.get(f, 0) for f in feature_order]], dtype=float)

    def _explain(self, features, profile, score):
        """Generate human-readable explanation"""
        reasons = []

        if features['avg_typing_speed'] > 100:
            reasons.append("Unusually fast typing")

        if features['copy_rate'] > 5:
            reasons.append("High copy activity (data exfil risk)")

        if features['hour_of_day'] < 6 or features['hour_of_day'] > 22:
            reasons.append("Access during unusual hours")

        if profile.baseline and score > 3:
            reasons.append("Significant deviation from normal behavior")

        return '; '.join(reasons) if reasons else 'Anomaly detected by ML model'


# Test the detector
if __name__ == '__main__':
    print("✅ Detector module loaded successfully!")
    detector = SimpleUEBADetector()
    print(f"   Model trained: {detector.is_trained}")
    print(f"   Active profiles: {len(detector.user_profiles)}")
