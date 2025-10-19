# synthetic_data.py - MINIMAL VERSION

import numpy as np
import pandas as pd

def generate_ueba_data(n_users=10, days=30):
    """
    Generate synthetic user behavior data
    """
    data = []
    
    for user_id in range(n_users):
        # Each user has their own "normal" pattern
        base_typing_speed = np.random.uniform(40, 70)
        base_click_rate = np.random.uniform(1, 3)
        preferred_hours = np.random.choice([9, 10, 14, 15, 16], size=3)
        
        # Generate normal behavior
        for day in range(days):
            for session in range(np.random.poisson(3)):  # 3 sessions/day avg
                
                # Normal behavior
                data.append({
                    'user_id': f'user_{user_id}',
                    'session_duration_min': np.random.normal(25, 5),
                    'hour_of_day': np.random.choice(preferred_hours),
                    'is_weekend': 0,
                    'avg_typing_speed': np.random.normal(base_typing_speed, 5),
                    'typing_speed_std': np.random.uniform(5, 15),
                    'click_rate': np.random.normal(base_click_rate, 0.5),
                    'copy_count': np.random.poisson(3),
                    'copy_rate': np.random.uniform(0.1, 0.5),
                    'unique_pages_visited': np.random.poisson(8),
                    'page_visit_rate': np.random.uniform(0.2, 0.5),
                    'label': 0  # normal
                })
        
        # Generate anomalous behavior (insider threat)
        for attack in range(3):  # 3 attacks per user
            data.append({
                'user_id': f'user_{user_id}',
                'session_duration_min': np.random.normal(60, 10),  # Long session
                'hour_of_day': np.random.choice([2, 3, 23]),  # Odd hours
                'is_weekend': 1,
                'avg_typing_speed': np.random.normal(90, 10),  # Fast (scripted)
                'typing_speed_std': np.random.uniform(1, 3),  # Very consistent
                'click_rate': np.random.normal(10, 2),  # Rapid clicking
                'copy_count': np.random.poisson(25),  # Mass copy
                'copy_rate': np.random.uniform(2, 5),
                'unique_pages_visited': np.random.poisson(40),  # Browsing many pages
                'page_visit_rate': np.random.uniform(1, 2),
                'label': 1  # anomaly
            })
    
    return pd.DataFrame(data)

if __name__ == '__main__':
    df = generate_ueba_data()
    df.to_csv('ueba_training_data.csv', index=False)
    print(f"Generated {len(df)} samples")
    print(f"Normal: {(df['label']==0).sum()}, Anomalous: {(df['label']==1).sum()}")