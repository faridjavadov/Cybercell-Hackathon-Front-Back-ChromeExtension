from fastapi import FastAPI, Depends, HTTPException
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
    label: str  # 'malicious', 'suspicious', 'benign'
    reason: str
    error: bool = False

app = FastAPI(
    title="Inspy Security Backend",
    description="Backend API for Inspy Security Chrome Extension",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Inspy Security Backend API", "status": "running"}

@app.post("/api/logs", response_model=LogResponse)
def create_log(log: LogCreate, db: Session = Depends(get_db)):
    db_log = Log(
        url=log.url,
        timestamp=log.timestamp,
        type=log.type,
        reason=log.reason
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

@app.get("/api/logs", response_model=PaginatedLogs)
def get_logs(
    page: int = 1, 
    per_page: int = 20, 
    log_type: str = None,
    reason: str = None,
    start_date: str = None,
    end_date: str = None,
    db: Session = Depends(get_db)
):
    # Validate pagination parameters
    if page < 1:
        page = 1
    if per_page < 1 or per_page > 100:
        per_page = 20
    
    # Calculate offset
    offset = (page - 1) * per_page
    
    # Build query with filters
    query = db.query(Log)
    
    # Apply filters
    if log_type and log_type != "all":
        query = query.filter(Log.type == log_type)
    
    if reason and reason != "all":
        query = query.filter(Log.reason.ilike(f"%{reason}%"))
    
    if start_date:
        try:
            start_datetime = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query = query.filter(Log.timestamp >= start_datetime)
        except ValueError:
            pass  # Invalid date format, ignore filter
    
    if end_date:
        try:
            end_datetime = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query = query.filter(Log.timestamp <= end_datetime)
        except ValueError:
            pass  # Invalid date format, ignore filter
    
    # Get total count with filters applied
    total = query.count()
    
    # Get logs with pagination and ordering
    logs = query.order_by(Log.timestamp.desc()).offset(offset).limit(per_page).all()
    
    # Calculate pagination info
    total_pages = (total + per_page - 1) // per_page
    has_next = page < total_pages
    has_prev = page > 1
    
    return PaginatedLogs(
        logs=logs,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        has_next=has_next,
        has_prev=has_prev
    )

@app.get("/api/logs/stats", response_model=LogStats)
def get_log_stats(db: Session = Depends(get_db)):
    total_logs = db.query(Log).count()
    malicious_logs = db.query(Log).filter(Log.type == "malicious").count()
    normal_logs = db.query(Log).filter(Log.type == "normal").count()
    
    recent_time = datetime.utcnow() - timedelta(hours=24)
    recent_logs = db.query(Log).filter(Log.timestamp >= recent_time).count()
    
    return LogStats(
        total_logs=total_logs,
        malicious_logs=malicious_logs,
        normal_logs=normal_logs,
        recent_logs=recent_logs
    )

@app.get("/api/logs/filter-options")
def get_filter_options(db: Session = Depends(get_db)):
    # Get unique types
    types = [row[0] for row in db.query(Log.type).distinct().all()]
    
    # Get unique reasons (limit to most common ones)
    reasons = [row[0] for row in db.query(Log.reason).distinct().limit(20).all()]
    
    # Get date range
    min_date = db.query(Log.timestamp).order_by(Log.timestamp.asc()).first()
    max_date = db.query(Log.timestamp).order_by(Log.timestamp.desc()).first()
    
    return {
        "types": types,
        "reasons": reasons,
        "date_range": {
            "min": min_date[0].isoformat() if min_date else None,
            "max": max_date[0].isoformat() if max_date else None
        }
    }

@app.get("/api/logs/malicious", response_model=List[LogResponse])
def get_malicious_logs(limit: int = 50, db: Session = Depends(get_db)):
    logs = db.query(Log).filter(Log.type == "malicious").limit(limit).all()
    return logs

@app.delete("/api/logs/{log_id}")
def delete_log(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    
    db.delete(log)
    db.commit()
    return {"message": "Log deleted successfully"}

@app.delete("/api/logs")
def clear_all_logs(db: Session = Depends(get_db)):
    db.query(Log).delete()
    db.commit()
    return {"message": "All logs cleared successfully"}

@app.get("/api/logs/stream")
def stream_logs(db: Session = Depends(get_db)):
    def event_generator():
        last_log_id = 0
        while True:
            try:
                # Get latest logs
                logs = db.query(Log).order_by(Log.id.desc()).limit(20).all()
                
                # Convert to dict format for JSON serialization
                logs_data = []
                for log in logs:
                    logs_data.append({
                        "id": log.id,
                        "url": log.url,
                        "timestamp": log.timestamp.isoformat(),
                        "type": log.type,
                        "reason": log.reason
                    })
                
                # Send data as SSE
                yield f"data: {json.dumps(logs_data)}\n\n"
                
                # Check for new logs every 2 seconds
                time.sleep(2)
                
            except Exception as e:
                print(f"SSE Error: {e}")
                yield f"data: {json.dumps([])}\n\n"
                time.sleep(5)

    return StreamingResponse(
        event_generator(), 
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Cache-Control"
        }
    )

# --- NEW SECURITY ENDPOINTS ---

@app.post("/api/reputation", response_model=UrlReputationResponse)
async def check_url_reputation(request: UrlReputationRequest):
    """
    Check URL reputation using VirusTotal and AbuseIPDB APIs
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
        
        # Initialize response
        reputation_data = {
            'malicious': False,
            'score': 0,
            'sources': {}
        }
        
        # Check with VirusTotal if API key is available
        if VT_API_KEY:
            try:
                async with httpx.AsyncClient() as client:
                    # Use direct URL lookup with base64 encoding
                    import base64
                    url_encoded = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
                    
                    # Get analysis results directly
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
                        
                        # Calculate threat score (0-100)
                        total_engines = sum(stats.values())
                        if total_engines > 0:
                            threat_score = (stats.get('malicious', 0) * 100 + stats.get('suspicious', 0) * 50) / total_engines
                            reputation_data['score'] = int(threat_score)
                            
                            # Mark as malicious if score > 10 OR any engine flags as malicious
                            if threat_score > 10 or stats.get('malicious', 0) > 0:
                                reputation_data['malicious'] = True
                    else:
                        print(f"VirusTotal API response: {analysis_response.status_code} - {analysis_response.text}")
                        reputation_data['sources']['virustotal'] = {'error': f'HTTP {analysis_response.status_code}'}
                                        
            except Exception as e:
                print(f"VirusTotal API error: {e}")
                reputation_data['sources']['virustotal'] = {'error': str(e)}
        
        # Check with AbuseIPDB if API key is available and we have a domain
        if ABUSEIPDB_API_KEY and domain:
            try:
                # Try to resolve domain to IP
                import socket
                try:
                    ip = socket.gethostbyname(domain)
                    
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
                            
                            # Mark as malicious if abuse confidence > 50% OR if there are many reports (>10)
                            if abuse_score > 50 or total_reports > 10:  
                                reputation_data['malicious'] = True
                                reputation_data['score'] = max(reputation_data['score'], abuse_score)
                                
                except socket.gaierror:
                    print(f"Could not resolve domain {domain} to IP")
                    pass
                    
            except Exception as e:
                print(f"AbuseIPDB API error: {e}")
                reputation_data['sources']['abuseipdb'] = {'error': str(e)}
        
        return UrlReputationResponse(**reputation_data)
        
    except Exception as e:
        print(f"URL reputation check error: {e}")
        return UrlReputationResponse(
            malicious=False, 
            score=0, 
            sources={'error': str(e)}, 
            error=True
        )

@app.post("/api/gpt/classify", response_model=GptClassificationResponse)
async def classify_content_with_gemini(request: GptClassificationRequest):
    """
    Classify text content using Google Gemini for security analysis
    """
    text = request.text
    
    try:
        # Validate input
        if not text or len(text) > 5000:
            return GptClassificationResponse(
                label='benign',
                reason='Text too long or empty',
                error=True
            )
        
        # Basic redaction of sensitive information
        redacted_text = redact_sensitive_content(text)
        
        if not GEMINI_API_KEY:
            # Fallback to basic heuristics if no API key
            return classify_with_heuristics(redacted_text)
        
        # Call Google Gemini API
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key={GEMINI_API_KEY}',
                headers={
                    'Content-Type': 'application/json'
                },
                json={
                    'contents': [{
                        'parts': [{
                            'text': f'''You are a security assistant. Analyze the given text and classify it as:
                            - "malicious": Contains malware, phishing, or clearly harmful content
                            - "suspicious": Contains potentially harmful patterns but not clearly malicious
                            - "benign": Safe, normal content
                            
                            Respond with JSON only: {{"label": "malicious|suspicious|benign", "reason": "brief explanation"}}
                            
                            Text to analyze: {redacted_text[:2000]}'''
                        }]
                    }],
                    'generationConfig': {
                        'temperature': 0.1,
                        'maxOutputTokens': 200
                    }
                },
                timeout=30.0
            )
            
            if response.status_code == 200:
                result = response.json()
                # Parse Gemini API response format
                try:
                    content = result['candidates'][0]['content']['parts'][0]['text']
                    
                    # Parse JSON response
                    classification = json.loads(content)
                    return GptClassificationResponse(
                        label=classification.get('label', 'benign'),
                        reason=classification.get('reason', 'No specific reason provided')
                    )
                except (KeyError, json.JSONDecodeError, IndexError) as e:
                    print(f"Gemini API response parsing error: {e}")
                    # Fallback if JSON parsing fails
                    return classify_with_heuristics(redacted_text)
            else:
                print(f"Gemini API error: {response.status_code} - {response.text}")
                return classify_with_heuristics(redacted_text)
                
    except Exception as e:
        print(f"Gemini classification error: {e}")
        return GptClassificationResponse(
            label='benign',
            reason=f'Classification failed: {str(e)}',
            error=True
        )

def redact_sensitive_content(text):
    """Redact sensitive information from text before sending to external APIs"""
    redacted = text
    
    # Redact API keys and tokens
    redacted = re.sub(r'(?i)(api[_-]?key|token|secret|password)[\s:=]{0,3}[A-Za-z0-9\-\._]{16,}', '[REDACTED_API_KEY]', redacted)
    redacted = re.sub(r'AKIA[0-9A-Z]{16}', '[REDACTED_AWS_KEY]', redacted)
    redacted = re.sub(r'ghp_[A-Za-z0-9]{36}', '[REDACTED_GITHUB_TOKEN]', redacted)
    redacted = re.sub(r'xox[baprs]-[A-Za-z0-9-]+', '[REDACTED_SLACK_TOKEN]', redacted)
    
    # Redact private keys
    redacted = re.sub(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----', '[REDACTED_PRIVATE_KEY]', redacted)
    
    # Redact JWTs
    redacted = re.sub(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$', '[REDACTED_JWT]', redacted, flags=re.MULTILINE)
    
    # Redact credit cards (keep last 4 digits)
    redacted = re.sub(r'\b(?:\d{4}[-\s]?){3}\d{4}\b', lambda m: '****-****-****-' + re.sub(r'\D', '', m.group())[-4:], redacted)
    
    # Redact SSNs
    redacted = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '***-**-****', redacted)
    
    return redacted

def classify_with_heuristics(text):
    """Fallback classification using basic heuristics"""
    malicious_patterns = [
        r'(?i)(malware|virus|trojan|backdoor|keylogger)',
        r'(?i)(phishing|scam|fraud|steal.*password)',
        r'(?i)(exploit|payload|shellcode)',
        r'(?i)(bitcoin.*wallet|send.*money)',
        r'(?i)(click.*here.*urgent|verify.*account.*immediately)'
    ]
    
    suspicious_patterns = [
        r'(?i)(suspicious|unusual|unexpected)',
        r'(?i)(download.*now|free.*offer)',
        r'(?i)(congratulations.*winner)',
        r'(?i)(limited.*time.*offer)'
    ]
    
    for pattern in malicious_patterns:
        if re.search(pattern, text):
            return GptClassificationResponse(
                label='malicious',
                reason=f'Detected malicious pattern: {pattern}'
            )
    
    for pattern in suspicious_patterns:
        if re.search(pattern, text):
            return GptClassificationResponse(
                label='suspicious',
                reason=f'Detected suspicious pattern: {pattern}'
            )
    
    return GptClassificationResponse(
        label='benign',
        reason='No suspicious patterns detected'
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
