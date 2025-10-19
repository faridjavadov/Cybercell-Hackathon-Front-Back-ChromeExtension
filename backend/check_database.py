#!/usr/bin/env python3
"""
Check what's in the database
"""
import sqlite3
import json
from datetime import datetime

def check_database():
    """Check what logs are in the database"""
    try:
        conn = sqlite3.connect('logs.db')
        cursor = conn.cursor()
        
        # Check if logs table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        if not cursor.fetchone():
            print("❌ No 'logs' table found in database")
            return
        
        # Count total logs
        cursor.execute("SELECT COUNT(*) FROM logs")
        total_logs = cursor.fetchone()[0]
        print(f"📊 Total logs in database: {total_logs}")
        
        if total_logs > 0:
            # Get recent logs
            cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 5")
            recent_logs = cursor.fetchall()
            
            print(f"\n📋 Recent logs:")
            for log in recent_logs:
                print(f"  ID: {log[0]}, URL: {log[1]}, Type: {log[3]}, Reason: {log[4]}")
        else:
            print("⚠️  No logs found in database")
            
        conn.close()
        
    except Exception as e:
        print(f"❌ Error checking database: {e}")

if __name__ == "__main__":
    check_database()
