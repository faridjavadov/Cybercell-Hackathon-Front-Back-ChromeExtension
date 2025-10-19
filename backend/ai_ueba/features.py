from datetime import datetime
import numpy as np
class BehaviorFeatures:
    """
    Extract features from user behavior events
    """
    
    @staticmethod
    def extract(events, user_id):
        """
        events: list of dicts with user actions
        returns: dict of features
        """
        
        if not events:
            return None
            
        features = {}
        
        # 1. TEMPORAL FEATURES
        timestamps = [e['timestamp'] for e in events]
        features['session_duration_min'] = (max(timestamps) - min(timestamps)) / 60000
        features['hour_of_day'] = datetime.fromtimestamp(timestamps[0]/1000).hour
        features['is_weekend'] = datetime.fromtimestamp(timestamps[0]/1000).weekday() >= 5
        
        # 2. TYPING BEHAVIOR
        typing_events = [e for e in events if e.get('type') == 'typing']
        if typing_events:
            speeds = [e['wpm'] for e in typing_events]
            features['avg_typing_speed'] = np.mean(speeds)
            features['typing_speed_std'] = np.std(speeds)
        else:
            features['avg_typing_speed'] = 0
            features['typing_speed_std'] = 0
        
        # 3. CLICK/INTERACTION PATTERNS
        click_events = [e for e in events if e.get('type') == 'click']
        features['click_rate'] = len(click_events) / (features['session_duration_min'] + 1)
        
        # 4. DATA ACCESS PATTERNS
        copy_events = [e for e in events if e.get('type') == 'copy']
        features['copy_count'] = len(copy_events)
        features['copy_rate'] = len(copy_events) / (features['session_duration_min'] + 1)
        
        # 5. NAVIGATION PATTERNS
        unique_urls = len(set([e.get('url', '') for e in events]))
        features['unique_pages_visited'] = unique_urls
        features['page_visit_rate'] = unique_urls / (features['session_duration_min'] + 1)
        
        return features