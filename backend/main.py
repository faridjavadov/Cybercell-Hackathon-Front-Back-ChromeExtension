from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from database import Base, engine, SessionLocal, Log, get_db
from models import LogCreate, LogResponse, LogStats, PaginatedLogs
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from typing import List
import json
import time
import os
import httpx
import asyncio
import re
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

Base.metadata.create_all(bind=engine)

# Environment variables for API keys
VT_API_KEY = os.getenv('VT_API_KEY')  # VirusTotal API key
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')  # Google Gemini API key
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')  # AbuseIPDB API key

# Pydantic models for new endpoints
class UrlReputationRequest(BaseModel):
    url: str

class UrlReputationResponse(BaseModel):
    malicious: bool
    score: int
    sources: dict
    error: bool = False

class GptClassificationRequest(BaseModel):
    text: str

class GptClassificationResponse(BaseModel):
    label: str
    reason: str
    error: bool = False

app = FastAPI(title="Inspy Security Backend", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database models and endpoints (keeping existing ones)
@app.get("/")
async def root():
    return {"message": "Inspy Security Backend API", "version": "1.0.0"}

@app.post("/api/logs", response_model=LogResponse)
async def create_log(log: LogCreate, db: Session = Depends(get_db)):
    db_log = Log(**log.dict())
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

@app.get("/api/logs", response_model=PaginatedLogs)
async def get_logs(page: int = 1, per_page: int = 20, db: Session = Depends(get_db)):
    offset = (page - 1) * per_page
    logs = db.query(Log).offset(offset).limit(per_page).all()
    total = db.query(Log).count()
    
    return PaginatedLogs(
        logs=logs,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=(total + per_page - 1) // per_page,
        has_next=page * per_page < total,
        has_prev=page > 1
    )

@app.get("/api/logs/stats", response_model=LogStats)
async def get_log_stats(db: Session = Depends(get_db)):
    total_logs = db.query(Log).count()
    malicious_logs = db.query(Log).filter(Log.type == "malicious").count()
    normal_logs = db.query(Log).filter(Log.type == "normal").count()
    
    # Recent logs (last 24 hours)
    recent_time = datetime.utcnow() - timedelta(hours=24)
    recent_logs = db.query(Log).filter(Log.timestamp >= recent_time).count()
    
    return LogStats(
        total_logs=total_logs,
        malicious_logs=malicious_logs,
        normal_logs=normal_logs,
        recent_logs=recent_logs
    )

@app.get("/api/logs/malicious", response_model=List[LogResponse])
async def get_malicious_logs(db: Session = Depends(get_db)):
    return db.query(Log).filter(Log.type == "malicious").all()

@app.delete("/api/logs/{log_id}")
async def delete_log(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    db.delete(log)
    db.commit()
    return {"message": "Log deleted successfully"}

@app.delete("/api/logs")
async def clear_all_logs(db: Session = Depends(get_db)):
    db.query(Log).delete()
    db.commit()
    return {"message": "All logs cleared successfully"}
    
@app.get("/api/logs/stream")
async def stream_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    log_type: str = Query("all"),
    reason: str = Query("all"),
    start_date: str = Query(None),
    end_date: str = Query(None)
):
    """
    Optimized Server-Sent Events endpoint for real-time logs with pagination
    """
    async def generate():
        last_logs_data = None
        last_stats = None
        initial_sent = False
        
        try:
            while True:
                db = SessionLocal()
                
                try:
                    # Build base query
                    query = db.query(Log)
                    
                    # Apply filters
                    if log_type != "all":
                        query = query.filter(Log.type == log_type)
                    if reason != "all":
                        query = query.filter(Log.reason == reason)
                    if start_date:
                        try:
                            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                            query = query.filter(Log.timestamp >= start_dt)
                        except ValueError:
                            pass
                    if end_date:
                        try:
                            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                            query = query.filter(Log.timestamp <= end_dt)
                        except ValueError:
                            pass
                    
                    # Get total count and pagination info
                    total_count = query.count()
                    total_pages = (total_count + per_page - 1) // per_page
                    offset = (page - 1) * per_page
                    
                    # Get paginated logs (newest first)
                    logs = query.order_by(Log.timestamp.desc()).offset(offset).limit(per_page).all()
                    
                    # Get stats (only for initial send or if changed)
                    if not initial_sent:
                        total_logs = db.query(Log).count()
                        malicious_logs = db.query(Log).filter(Log.type == 'malicious').count()
                        normal_logs = db.query(Log).filter(Log.type == 'normal').count()
                        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
                        recent_logs = db.query(Log).filter(Log.timestamp >= recent_cutoff).count()
                        
                        current_stats = {
                            "type": "stats",
                            "total_logs": total_logs,
                            "malicious_logs": malicious_logs,
                            "normal_logs": normal_logs,
                            "recent_logs": recent_logs,
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        
                        yield f"data: {json.dumps(current_stats)}\n\n"
                        last_stats = current_stats
                    
                    # Prepare logs data
                    current_logs_data = {
                        "type": "logs",
                        "logs": [{
                            "id": log.id,
                            "url": log.url,
                            "timestamp": log.timestamp.isoformat(),
                            "type": log.type,
                            "reason": log.reason
                        } for log in logs],
                        "pagination": {
                            "page": page,
                            "per_page": per_page,
                            "total": total_count,
                            "total_pages": total_pages,
                            "has_next": page < total_pages,
                            "has_prev": page > 1
                        },
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    # Send logs data (always send on page change)
                    if last_logs_data != current_logs_data:
                        yield f"data: {json.dumps(current_logs_data)}\n\n"
                        last_logs_data = current_logs_data
                        initial_sent = True
                    
                    # Send heartbeat if no changes
                    if last_logs_data == current_logs_data and initial_sent:
                        heartbeat = {
                            'type': 'heartbeat', 
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        yield f"data: {json.dumps(heartbeat)}\n\n"
                    
                finally:
                    db.close()
                
                # Check every 10 seconds for updates
                await asyncio.sleep(10)
                
        except asyncio.CancelledError:
            print("SSE connection closed by client")
        except Exception as e:
            error_msg = {
                'type': 'error', 
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
            yield f"data: {json.dumps(error_msg)}\n\n"
            print(f"SSE error: {e}")
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "Content-Type": "text/event-stream",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        }
    )

@app.get("/api/logs/filter-options")
async def get_filter_options(db: Session = Depends(get_db)):
    """
    Get available filter options (log types and reasons)
    """
    try:
        # Get unique log types
        log_types = db.query(Log.type).distinct().all()
        
        # Get unique reasons (excluding None/null values)
        reasons = db.query(Log.reason).filter(Log.reason != None).filter(Log.reason != "None").distinct().all()
        
        return {
            "log_types": [t[0] for t in log_types if t[0]],
            "reasons": [r[0] for r in reasons if r[0]]
        }
    except Exception as e:
        print(f"Error fetching filter options: {e}")
        return {
            "log_types": [],
            "reasons": []
        }
# NEW SIMPLIFIED REPUTATION CHECKING
@app.post("/api/reputation", response_model=UrlReputationResponse)
async def check_url_reputation(request: UrlReputationRequest):
    """
    Check URL reputation using VirusTotal and AbuseIPDB APIs with OR logic
    """
    url = request.url
    
    try:
        # Basic URL validation
        if not url or len(url) > 2048:
            return UrlReputationResponse(
                malicious=False, 
                score=0, 
                sources={}, 
                error=True
            )
        
        # Extract domain and IP for checking
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Skip localhost and local IPs - they're not malicious
        if (domain == 'localhost' or 
            domain.startswith('127.') or 
            domain.startswith('192.168.') or 
            domain.startswith('10.') or
            domain.startswith('172.')):
            return UrlReputationResponse(
                malicious=False, 
                score=0, 
                sources={'local': 'localhost or private IP'}, 
                error=False
            )
        
        # Initialize response
        reputation_data = {
            'malicious': False,
            'score': 0,
            'sources': {}
        }
        
        # COMBINED REPUTATION CHECKING FUNCTION
        async def check_reputation_combined():
            """Check URL reputation using both VirusTotal and AbuseIPDB with OR logic"""
            vt_malicious = False
            vt_score = 0
            abuse_malicious = False
            abuse_score = 0
            
            # Check VirusTotal
            if VT_API_KEY:
                try:
                    async with httpx.AsyncClient() as client:
                        import base64
                        url_encoded = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
                        
                        analysis_response = await client.get(
                            f'https://www.virustotal.com/api/v3/urls/{url_encoded}',
                            headers={'x-apikey': VT_API_KEY}
                        )
                        
                        if analysis_response.status_code == 200:
                            analysis_data = analysis_response.json()
                            stats = analysis_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                            
                            reputation_data['sources']['virustotal'] = {
                                'malicious': stats.get('malicious', 0),
                                'suspicious': stats.get('suspicious', 0),
                                'harmless': stats.get('harmless', 0),
                                'undetected': stats.get('undetected', 0)
                            }
                            
                            # Calculate VirusTotal threat score
                            total_engines = sum(stats.values())
                            if total_engines > 0:
                                vt_score = (stats.get('malicious', 0) * 100 + stats.get('suspicious', 0) * 50) / total_engines
                                vt_malicious = vt_score > 10
                        else:
                            reputation_data['sources']['virustotal'] = {'error': f'HTTP {analysis_response.status_code}'}
                except Exception as e:
                    reputation_data['sources']['virustotal'] = {'error': str(e)}
            
            # Check AbuseIPDB
            if ABUSEIPDB_API_KEY:
                try:
                    import socket
                    import ipaddress
                    
                    # Get IP address
                    try:
                        ip_obj = ipaddress.ip_address(domain)
                        ip = str(ip_obj)
                    except ValueError:
                        try:
                            ip = socket.gethostbyname(domain)
                        except socket.gaierror:
                            ip = None
                    
                    if ip:
                        async with httpx.AsyncClient() as client:
                            response = await client.get(
                                f'https://api.abuseipdb.com/api/v2/check',
                                headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
                                params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''}
                            )
                            
                            if response.status_code == 200:
                                abuse_data = response.json()
                                abuse_score = abuse_data.get('data', {}).get('abuseConfidencePercentage', 0)
                                total_reports = abuse_data.get('data', {}).get('totalReports', 0)
                                
                                reputation_data['sources']['abuseipdb'] = {
                                    'abuse_confidence': abuse_score,
                                    'total_reports': total_reports,
                                    'ip': ip
                                }
                                
                                # AbuseIPDB malicious if confidence > 25% OR reports > 5
                                abuse_malicious = abuse_score > 25 or total_reports > 5
                            else:
                                reputation_data['sources']['abuseipdb'] = {'error': f'HTTP {response.status_code}'}
                except Exception as e:
                    reputation_data['sources']['abuseipdb'] = {'error': str(e)}
            
            # COMBINED LOGIC: Malicious if VirusTotal OR AbuseIPDB flags it
            is_malicious = vt_malicious or abuse_malicious
            final_score = max(vt_score, abuse_score)
            
            if is_malicious:
                reputation_data['malicious'] = True
                reputation_data['score'] = int(final_score)
                print(f"Debug: URL flagged as malicious - VT: {vt_malicious}({vt_score}), AbuseIPDB: {abuse_malicious}({abuse_score})")
            
            return is_malicious, final_score
        
        # Run combined reputation check
        await check_reputation_combined()
        
        # Local detection fallback (only if no API detection)
        if not reputation_data.get('malicious', False):
            if not any(domain in url.lower() for domain in ['google.test', 'testing.google.test', 'malware.testing.google.test']):
                malicious_patterns = ['malware', 'virus', 'trojan', 'phishing', 'scam', 'fake', 'malicious', 'suspicious']
                if any(pattern in url.lower() for pattern in malicious_patterns):
                    print(f"Debug: Local detection triggered for pattern in URL: {url}")
                    reputation_data['malicious'] = True
                    reputation_data['score'] = 80
                    reputation_data['sources']['local'] = 'Local pattern detection'
        
        return UrlReputationResponse(**reputation_data)
        
    except Exception as e:
        print(f"URL reputation check error: {e}")
        return UrlReputationResponse(
            malicious=False, 
            score=0, 
            sources={'error': str(e)}, 
            error=True
        )

# GPT Classification endpoint (keeping existing)
@app.post("/api/gpt/classify", response_model=GptClassificationResponse)
async def classify_content_with_gemini(request: GptClassificationRequest):
    """
    Classify text content using Google Gemini for security analysis
    """
    text = request.text
    
    if not GEMINI_API_KEY:
        return GptClassificationResponse(
            label="error",
            reason="Gemini API key not configured",
            error=True
        )
    
    try:
        # Use Google Gemini API for classification
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        
        model = genai.GenerativeModel('gemini-pro')
        
        prompt = f"""
        Analyze the following text for security threats and classify it as one of:
        - "malicious": Contains malware, phishing, or other security threats
        - "suspicious": Potentially harmful but not clearly malicious
        - "safe": No security concerns detected
        
        Text to analyze: {text}
        
        Respond with only the classification and a brief reason.
        Format: CLASSIFICATION: reason
        """
        
        response = model.generate_content(prompt)
        result = response.text.strip()
        
        if "malicious" in result.lower():
            return GptClassificationResponse(
                label="malicious",
                reason=result,
                error=False
            )
        elif "suspicious" in result.lower():
            return GptClassificationResponse(
                label="suspicious", 
                reason=result,
                error=False
            )
        else:
            return GptClassificationResponse(
                label="safe",
                reason=result,
                error=False
            )
            
    except Exception as e:
        print(f"Gemini classification error: {e}")
        return GptClassificationResponse(
            label="error",
            reason=f"Classification failed: {str(e)}",
            error=True
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
