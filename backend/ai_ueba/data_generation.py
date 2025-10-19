import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta

# Configuration
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

class DataGenerator:
    def __init__(self):
        self.normal_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
            'amazon.com', 'wikipedia.org', 'reddit.com', 'github.com',
            'stackoverflow.com', 'linkedin.com', 'netflix.com', 'instagram.com'
        ]
        
        self.suspicious_domains = [
            'grandpashabet7003.com', 'phishing-site.xyz', 'malware-download.tk',
            'fake-bank.com', 'crypto-scam.net', 'suspicious-betting.org',
            'ad-fraud.click', 'keylogger-site.info'
        ]
        
        self.browsers = ['Chrome', 'Firefox', 'Edge', 'Safari']
        self.os_list = ['Windows', 'macOS', 'Linux']
        self.locales = ['en-US', 'en-GB', 'tr-TR', 'az-AZ', 'ru-RU']
        
    def generate_normal_session(self, user_id, session_id, start_time):
        """Generate normal user browsing session"""
        num_events = random.randint(10, 50)
        logs = []
        current_time = start_time
        
        session_domains = random.sample(self.normal_domains, random.randint(2, 3))
        
        for i in range(num_events):
            domain = random.choice(session_domains)
            
            # Normal behavior: 95% normal, 5% suspicious (false positives)
            is_suspicious = random.random() < 0.05
            
            log = {
                'user_id': user_id,
                'session_id': session_id,
                'timestamp': current_time.isoformat(),
                'url': f'https://{domain}/page{random.randint(1,100)}',
                'domain': domain,
                'event_type': random.choice(['page_open', 'click', 'scroll', 'form_submit']),
                'suspicious_flag': 1 if is_suspicious else 0,
                'reason': 'obfuscation detected' if is_suspicious else 'normal',
                'time_on_page': random.randint(3, 60),  # seconds
                'browser': random.choice(self.browsers),
                'os': random.choice(self.os_list),
                'locale': random.choice(self.locales),
                'label': 0  # 0 = normal session
            }
            
            logs.append(log)
            
            # Normal browsing intervals: 2-30 seconds
            current_time += timedelta(seconds=random.randint(2, 30))
        
        return logs
    
    def generate_phishing_attack(self, user_id, session_id, start_time):
        """Generate phishing attack pattern"""
        num_events = random.randint(20, 60)
        logs = []
        current_time = start_time
        
        # Start normal
        normal_phase = random.randint(5, 10)
        for i in range(normal_phase):
            domain = random.choice(self.normal_domains)
            log = {
                'user_id': user_id,
                'session_id': session_id,
                'timestamp': current_time.isoformat(),
                'url': f'https://{domain}/page{random.randint(1,100)}',
                'domain': domain,
                'event_type': 'page_open',
                'suspicious_flag': 0,
                'reason': 'normal',
                'time_on_page': random.randint(5, 20),
                'browser': random.choice(self.browsers),
                'os': random.choice(self.os_list),
                'locale': random.choice(self.locales),
                'label': 1
            }
            logs.append(log)
            current_time += timedelta(seconds=random.randint(5, 15))
        
        attack_domain = random.choice(self.suspicious_domains)
        for i in range(normal_phase, num_events):
            is_suspicious = random.random() < 0.7  # 70% suspicious during attack
            
            log = {
                'user_id': user_id,
                'session_id': session_id,
                'timestamp': current_time.isoformat(),
                'url': f'https://{attack_domain}/login?token={random.randint(1000,9999)}',
                'domain': attack_domain,
                'event_type': random.choice(['page_open', 'form_submit', 'api_call']),
                'suspicious_flag': 1 if is_suspicious else 0,
                'reason': random.choice([
                    'js_evasion: obfuscation',
                    'eval detected',
                    'base64 encoding',
                    'hidden iframe'
                ]) if is_suspicious else 'normal',
                'time_on_page': random.randint(1, 5),  # Quick - automated
                'browser': random.choice(self.browsers),
                'os': random.choice(self.os_list),
                'locale': random.choice(self.locales),
                'label': 1
            }
            logs.append(log)
            
            # Fast intervals during attack
            current_time += timedelta(milliseconds=random.randint(500, 3000))
        
        return logs
    
    def generate_malware_session(self, user_id, session_id, start_time):
        """Generate malware/cryptojacking pattern"""
        num_events = random.randint(30, 80)
        logs = []
        current_time = start_time
        
        # Normal browsing first
        for i in range(10):
            domain = random.choice(self.normal_domains)
            log = {
                'user_id': user_id,
                'session_id': session_id,
                'timestamp': current_time.isoformat(),
                'url': f'https://{domain}/page{random.randint(1,100)}',
                'domain': domain,
                'event_type': 'page_open',
                'suspicious_flag': 0,
                'reason': 'normal',
                'time_on_page': random.randint(5, 30),
                'browser': random.choice(self.browsers),
                'os': random.choice(self.os_list),
                'locale': random.choice(self.locales),
                'label': 1
            }
            logs.append(log)
            current_time += timedelta(seconds=random.randint(5, 20))
        
        # Malware infection - burst of suspicious activity
        malware_domain = random.choice(self.suspicious_domains)
        for i in range(10, num_events):
            log = {
                'user_id': user_id,
                'session_id': session_id,
                'timestamp': current_time.isoformat(),
                'url': f'https://{malware_domain}/script.js',
                'domain': malware_domain,
                'event_type': random.choice(['api_call', 'network_request']),
                'suspicious_flag': 1,
                'reason': random.choice([
                    'cryptocurrency mining',
                    'data exfiltration',
                    'keylogger detected',
                    'js_evasion: obfuscation'
                ]),
                'time_on_page': random.randint(1, 3),
                'browser': random.choice(self.browsers),
                'os': random.choice(self.os_list),
                'locale': random.choice(self.locales),
                'label': 1
            }
            logs.append(log)
            
            # Very fast - automated malware behavior
            current_time += timedelta(milliseconds=random.randint(200, 1000))
        
        return logs
    
    def generate_dataset(self, num_sessions=2000):
        """Generate complete dataset"""
        print(f"Generating {num_sessions} sessions...")
        print("-" * 60)
        
        all_logs = []
        current_time = datetime(2025, 1, 1, 9, 0, 0)
        
        # 70% normal, 20% phishing, 10% malware
        normal_count = int(num_sessions * 0.70)
        phishing_count = int(num_sessions * 0.20)
        malware_count = num_sessions - normal_count - phishing_count
        
        session_id = 1
        
        # Generate normal sessions
        print(f"📊 Generating {normal_count} normal sessions...")
        for i in range(normal_count):
            user_id = f"user_{random.randint(1, 500)}"
            logs = self.generate_normal_session(user_id, f"session_{session_id}", current_time)
            all_logs.extend(logs)
            session_id += 1
            current_time += timedelta(minutes=random.randint(30, 180))
        
        # Generate phishing attacks
        print(f"⚠️  Generating {phishing_count} phishing attacks...")
        for i in range(phishing_count):
            user_id = f"user_{random.randint(1, 500)}"
            logs = self.generate_phishing_attack(user_id, f"session_{session_id}", current_time)
            all_logs.extend(logs)
            session_id += 1
            current_time += timedelta(minutes=random.randint(30, 180))
        
        # Generate malware sessions
        print(f"🦠 Generating {malware_count} malware sessions...")
        for i in range(malware_count):
            user_id = f"user_{random.randint(1, 500)}"
            logs = self.generate_malware_session(user_id, f"session_{session_id}", current_time)
            all_logs.extend(logs)
            session_id += 1
            current_time += timedelta(minutes=random.randint(30, 180))
        
        print("-" * 60)
        print(f"✅ Generated {len(all_logs)} total events")
        
        return pd.DataFrame(all_logs)


if __name__ == '__main__':
    print("\n" + "="*60)
    print("SYNTHETIC DATA GENERATION")
    print("="*60 + "\n")
    
    generator = DataGenerator()
    
    # Generate dataset
    df = generator.generate_dataset(num_sessions=3000)  # 3000 sessions = ~50k+ rows
    
    # Show statistics
    print("\n📊 Dataset Statistics:")
    print(f"Total rows: {len(df)}")
    print(f"Total sessions: {df['session_id'].nunique()}")
    print(f"Total users: {df['user_id'].nunique()}")
    print(f"\nLabel distribution:")
    print(df['label'].value_counts())
    print(f"\nSuspicious events: {df['suspicious_flag'].sum()} ({df['suspicious_flag'].mean()*100:.1f}%)")
    
    # Save to CSV
    df.to_csv('synthetic_extension_events.csv', index=False)
    print(f"\n💾 Saved to: synthetic_training_data.csv")
    
    # Show sample
    print("\n🔍 Sample data:")
    print(df.head(10))
    
    print("\n" + "="*60)
    print("✅ COMPLETE!")
    print("="*60)
