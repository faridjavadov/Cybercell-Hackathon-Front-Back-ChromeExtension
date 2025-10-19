#!/usr/bin/env python3
"""
Test script for AI UEBA service
"""

import requests
import json

def test_ai_service():
    """Test the AI UEBA service"""
    
    # Test data - sample logs
    test_logs = [
        {
            "id": 1,
            "url": "https://www.ebay.com/",
            "timestamp": "2025-10-19T07:49:15.000Z",
            "type": "normal",
            "reason": "Page navigation"
        },
        {
            "id": 2,
            "url": "https://www.ebay.com/search",
            "timestamp": "2025-10-19T07:49:20.000Z",
            "type": "suspicious",
            "reason": "js_evasion: obfuscation"
        },
        {
            "id": 3,
            "url": "https://www.ebay.com/item/123",
            "timestamp": "2025-10-19T07:49:25.000Z",
            "type": "normal",
            "reason": "Page navigation"
        }
    ]
    
    # Test request
    test_request = {
        "logs": test_logs
    }
    
    try:
        print("Testing AI UEBA service...")
        print(f"Request: {json.dumps(test_request, indent=2)}")
        
        # Test health endpoint
        health_response = requests.get("http://localhost:8001/health", timeout=5)
        print(f"Health check: {health_response.status_code} - {health_response.json()}")
        
        # Test analysis endpoint
        analysis_response = requests.post(
            "http://localhost:8001/analyze-simple",
            json=test_request,
            timeout=10
        )
        
        print(f"Analysis response: {analysis_response.status_code}")
        if analysis_response.status_code == 200:
            result = analysis_response.json()
            print(f"Result: {json.dumps(result, indent=2)}")
        else:
            print(f"Error: {analysis_response.text}")
            
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to AI service. Make sure it's running on port 8001")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_ai_service()
