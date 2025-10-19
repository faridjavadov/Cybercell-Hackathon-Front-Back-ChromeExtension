# 🚀 InspyGuard Deployment Guide

## Quick Deployment Options

### Option 1: Docker Compose (Recommended)

```bash
# 1. Clone and setup
git clone <repository-url>
cd InspyGuard

# 2. Configure environment
cp .env.example .env
# Edit .env with your API keys

# 3. Deploy
docker-compose up -d

# 4. Verify
curl http://localhost:8000/
curl http://localhost:8001/health
```

### Option 2: Manual Setup

```bash
# Backend
cd backend
pip install -r requirements.txt
python main.py &

# AI Service
cd backend/ai_ueba
pip install -r requirements.txt
python ai_api.py &

# Frontend
cd frontend
npm install
npm start
```

## Environment Configuration

### Required API Keys

```env
# .env file
VT_API_KEY=your_virustotal_api_key
GEMINI_API_KEY=your_gemini_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

### Service Ports

| Service | Port | URL |
|---------|------|-----|
| Backend API | 8000 | http://localhost:8000 |
| AI UEBA Service | 8001 | http://localhost:8001 |
| Frontend Dashboard | 3000 | http://localhost:3000 |

## Production Checklist

- [ ] Set up HTTPS certificates
- [ ] Configure environment variables
- [ ] Set up database backups
- [ ] Configure monitoring
- [ ] Test all endpoints
- [ ] Load Chrome extension
- [ ] Verify security features

## Health Checks

```bash
# Backend health
curl http://localhost:8000/

# AI service health  
curl http://localhost:8001/health

# Frontend health
curl http://localhost:3000
```

## Troubleshooting

### Services not starting
```bash
docker-compose logs
docker-compose restart
```

### API errors
- Check API keys in `.env`
- Verify rate limits
- Check service logs

### Extension issues
- Reload extension in Chrome
- Check browser console
- Verify backend connectivity
