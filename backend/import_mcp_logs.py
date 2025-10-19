#!/usr/bin/env python3
"""
Import MCP logs from ../logs/mcp.log into backend SQLite database
"""

import sqlite3
import re
from datetime import datetime
import os

def parse_mcp_log_line(line):
    """Parse a single MCP log line and extract relevant information"""
    try:
        # Pattern: "2025-10-19 07:41:41,374 [INFO] Executing command: nmap -sV -p 80,443,8080 127.0.0.1"
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3}) \[(\w+)\] (.+)'
        match = re.match(pattern, line.strip())
        
        if not match:
            return None
            
        timestamp_str = match.group(1)
        level = match.group(3)
        message = match.group(4)
        
        # Extract command and tool information
        command = None
        tool = None
        target = None
        
        if "Executing command:" in message:
            command = message.replace("Executing command:", "").strip()
            
            # Extract tool name
            if command.startswith("nmap"):
                tool = "nmap"
            elif command.startswith("dirb"):
                tool = "dirb"
            elif command.startswith("gobuster"):
                tool = "gobuster"
            elif command.startswith("hydra"):
                tool = "hydra"
            elif command.startswith("curl"):
                tool = "curl"
            
            # Extract target (IP/URL)
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            url_pattern = r'https?://[^\s]+'
            
            ip_match = re.search(ip_pattern, command)
            url_match = re.search(url_pattern, command)
            
            if ip_match:
                target = ip_match.group()
            elif url_match:
                target = url_match.group()
        
        return {
            "timestamp": timestamp_str,
            "level": level,
            "message": message,
            "command": command,
            "tool": tool,
            "target": target
        }
    except Exception as e:
        print(f"Error parsing MCP log line: {e}")
        return None

def import_mcp_logs():
    """Import MCP logs from file to backend database"""
    
    # Check if log file exists
    log_file_path = "logs/mcp.log"
    if not os.path.exists(log_file_path):
        print(f"Error: MCP log file not found at {log_file_path}")
        return
    
    # Connect to backend database
    db_path = "logs.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create mcp_logs table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mcp_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            level VARCHAR NOT NULL,
            message TEXT NOT NULL,
            command VARCHAR,
            tool VARCHAR,
            target VARCHAR
        )
    ''')
    
    imported_count = 0
    
    try:
        with open(log_file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                
                parsed_log = parse_mcp_log_line(line)
                if parsed_log:
                    # Check if log already exists (avoid duplicates)
                    cursor.execute('''
                        SELECT id FROM mcp_logs 
                        WHERE timestamp = ? AND message = ?
                    ''', (parsed_log['timestamp'], parsed_log['message']))
                    
                    if not cursor.fetchone():
                        # Insert MCP log
                        cursor.execute('''
                            INSERT INTO mcp_logs (timestamp, level, message, command, tool, target)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            parsed_log['timestamp'],
                            parsed_log['level'],
                            parsed_log['message'],
                            parsed_log['command'],
                            parsed_log['tool'],
                            parsed_log['target']
                        ))
                        imported_count += 1
        
        conn.commit()
        print(f"Successfully imported {imported_count} MCP logs into backend database")
        
    except Exception as e:
        conn.rollback()
        print(f"Error importing MCP logs: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    import_mcp_logs()
