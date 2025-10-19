#!/usr/bin/env python3
"""
AI UEBA API Server
Provides machine learning-based user behavior analytics
"""

import json
import pandas as pd
import joblib
from datetime import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import uvicorn
import os

app = FastAPI(title="AI UEBA Service", version="1.0.0")

# Global variables for models
rf_model = None
iso_model = None
feature_columns = None

class LogEntry(BaseModel):
    id: int
    url: str
    timestamp: str
    type: str
    reason: str

class UEBARequest(BaseModel):
    logs: List[LogEntry]

class UEBAResponse(BaseModel):
    anomaly_flag: int
    predicted_uninstall: int
    uninstall_prob: float
    session_duration_ms: float
    num_events: int
    error_rate: float

def load_models():
    """Load the trained ML models"""
    global rf_model, iso_model, feature_columns
    
    try:
        # Load models (check if files exist)
        if os.path.exists("uninstall_predictor.pkl"):
            rf_model = joblib.load("uninstall_predictor.pkl")
        else:
            print("Warning: uninstall_predictor.pkl not found, using dummy model")
            rf_model = None
            
        if os.path.exists("isolation_forest_model.pkl"):
            iso_model = joblib.load("isolation_forest_model.pkl")
        else:
            print("Warning: isolation_forest_model.pkl not found, using dummy model")
            iso_model = None
            
        if os.path.exists("feature_columns.json"):
            with open("feature_columns.json", "r") as f:
                feature_columns = json.load(f)
        else:
            print("Warning: feature_columns.json not found, using default features")
            feature_columns = [
                "session_duration_ms", "num_events_in_session", "error_rate", 
                "avg_event_gap", "events_per_sec", "click", "js_evasion"
            ]
            
        print("Models loaded successfully")
        
    except Exception as e:
        print(f"Error loading models: {e}")
        # Set defaults for development
        rf_model = None
        iso_model = None
        feature_columns = [
            "session_duration_ms", "num_events_in_session", "error_rate", 
            "avg_event_gap", "events_per_sec", "click", "js_evasion"
        ]

def extract_features(logs: List[LogEntry]) -> Dict[str, Any]:
    """Extract features from log entries"""
    if not logs:
        return {}
    
    # Convert to DataFrame
    df = pd.DataFrame([log.dict() for log in logs])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")
    
    # Calculate session metrics
    session_duration_ms = (df["timestamp"].max() - df["timestamp"].min()).total_seconds() * 1000
    num_events = len(df)
    error_rate = (df["type"] == "suspicious").sum() / num_events if num_events > 0 else 0
    avg_event_gap = df["timestamp"].diff().dt.total_seconds().fillna(0).mean() * 1000
    events_per_sec = num_events / (session_duration_ms / 1000) if session_duration_ms > 0 else 0
    
    # Count event types
    click_count = (df["reason"] == "Page navigation").sum()
    js_evasion_count = df["reason"].str.contains("js_evasion", na=False).sum()
    
    features = {
        "session_duration_ms": session_duration_ms,
        "num_events_in_session": num_events,
        "error_rate": error_rate,
        "avg_event_gap": avg_event_gap,
        "events_per_sec": events_per_sec,
        "click": click_count,
        "js_evasion": js_evasion_count
    }
    
    return features

def predict_ueba(features: Dict[str, Any]) -> UEBAResponse:
    """Make UEBA predictions using loaded models"""
    
    # If models are not loaded, return default values
    if rf_model is None or iso_model is None:
        return UEBAResponse(
            anomaly_flag=0,
            predicted_uninstall=0,
            uninstall_prob=0.1,
            session_duration_ms=features.get("session_duration_ms", 0),
            num_events=features.get("num_events_in_session", 0),
            error_rate=features.get("error_rate", 0)
        )
    
    try:
        # Prepare features for prediction
        X_new = pd.DataFrame([features])
        
        for col in feature_columns:
            if col not in X_new.columns:
                X_new[col] = 0
        X_new = X_new[feature_columns]
        
        # Make predictions
        anomaly_flag = iso_model.predict(X_new)[0]
        anomaly_flag = 1 if anomaly_flag == -1 else 0
        
        predicted_uninstall = int(rf_model.predict(X_new)[0])
        uninstall_prob = float(rf_model.predict_proba(X_new)[:,1][0])
        
        return UEBAResponse(
            anomaly_flag=anomaly_flag,
            predicted_uninstall=predicted_uninstall,
            uninstall_prob=uninstall_prob,
            session_duration_ms=features.get("session_duration_ms", 0),
            num_events=features.get("num_events_in_session", 0),
            error_rate=features.get("error_rate", 0)
        )
        
    except Exception as e:
        print(f"Error in prediction: {e}")
        # Return safe defaults
        return UEBAResponse(
            anomaly_flag=0,
            predicted_uninstall=0,
            uninstall_prob=0.1,
            session_duration_ms=features.get("session_duration_ms", 0),
            num_events=features.get("num_events_in_session", 0),
            error_rate=features.get("error_rate", 0)
        )

@app.on_event("startup")
async def startup_event():
    """Load models on startup"""
    load_models()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "ai-ueba"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "AI UEBA Service", "version": "1.0.0"}

@app.post("/analyze", response_model=UEBAResponse)
async def analyze_behavior(request: UEBARequest):
    """Analyze user behavior and return UEBA predictions"""
    try:
        # Extract features from logs
        features = extract_features(request.logs)
        
        # Make predictions
        result = predict_ueba(features)
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze-simple")
async def analyze_simple(request: UEBARequest):
    """Simple analysis endpoint for backward compatibility"""
    try:
        # Extract features from logs
        features = extract_features(request.logs)
        
        # Make predictions
        result = predict_ueba(features)
        
        # Return in the format expected by the backend
        return {
            "anomaly_flag": result.anomaly_flag,
            "predicted_uninstall": result.predicted_uninstall,
            "uninstall_prob": result.uninstall_prob
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
