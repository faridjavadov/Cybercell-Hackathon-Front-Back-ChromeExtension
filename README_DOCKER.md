# Inspy Security - Docker Deployment

Complete Docker setup for the Inspy Security system with Chrome Extension, FastAPI Backend, and React Dashboard.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Chrome        │    │   Docker        │    │   Docker        │
│   Extension     │───▶│   Backend       │◀───│   Frontend      │
│   (Static)      │    │   (FastAPI)     │    │   (React)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   SQLite DB     │
                       │   (Volume)      │
                       └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker Desktop installed and running
- Node.js (for building frontend)
- Python 3.11+

### 1. Build and Start Everything
```bash
python docker_start.py
```

This will:
- ✅ Build the React frontend
- ✅ Package the Chrome extension
- ✅ Build Docker containers
- ✅ Start all services
- ✅ Test connectivity

### 2. Access the System
- **Dashboard:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs
- **Chrome Extension:** `build/InspyGuard_extension/`

## 📁 Project Structure

```
Cybercell_Hackathon/
├── InspyGuard_extension/          # Chrome Extension (static files)
├── backend/                       # FastAPI Backend
│   ├── Dockerfile
│   ├── main.py
│   ├── database.py
│   └── requirements.txt
├── frontend/                      # React Frontend
│   ├── Dockerfile
│   ├── nginx.conf
│   └── src/
├── nginx/                         # Reverse Proxy (optional)
│   └── nginx.conf
├── build/                         # Built artifacts
│   └── InspyGuard_extension/
├── docker-compose.yml
├── docker_start.py
└── README_DOCKER.md
```

## 🐳 Docker Services

### Backend Service
- **Image:** Custom FastAPI
- **Port:** 8000
- **Features:** 
  - REST API endpoints
  - Server-Sent Events (SSE)
  - SQLite database
  - CORS enabled

### Frontend Service
- **Image:** Nginx + React build
- **Port:** 3000
- **Features:**
  - Static React app
  - Nginx reverse proxy
  - Gzip compression
  - Security headers

### Optional: Nginx Reverse Proxy
- **Image:** Nginx Alpine
- **Port:** 80
- **Features:**
  - Single entry point
  - Load balancing
  - SSL termination ready

## 🔧 Management Commands

### Start Services
```bash
python docker_start.py
```

### Stop Services
```bash
python docker_start.py stop
```

### View Logs
```bash
python docker_start.py logs
```

### Restart Services
```bash
python docker_start.py restart
```

### Manual Docker Commands
```bash
# Build containers
docker-compose build

# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f

# Rebuild and restart
docker-compose up --build -d
```

## 🔌 API Endpoints

### Backend API (http://localhost:8000)
- `GET /` - Health check
- `POST /api/logs` - Create security log
- `GET /api/logs` - Get all logs
- `GET /api/logs/stats` - Get statistics
- `GET /api/logs/stream` - SSE stream
- `GET /docs` - API documentation

### Frontend (http://localhost:3000)
- `GET /` - Dashboard
- Real-time SSE connection to backend

## 📦 Chrome Extension Installation

1. **Load Extension:**
   - Open Chrome → `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select `build/InspyGuard_extension/`

2. **Test Extension:**
   - Visit any website with file upload
   - Try uploading large files or dangerous extensions
   - Watch real-time logs in dashboard

## 🔍 Monitoring & Debugging

### Check Service Status
```bash
docker-compose ps
```

### View Service Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
```

### Access Container Shell
```bash
# Backend container
docker-compose exec backend bash

# Frontend container
docker-compose exec frontend sh
```

### Database Access
```bash
# SQLite database is mounted as volume
# Located at: ./backend/logs.db
```

## 🚀 Production Deployment

### With Reverse Proxy
```bash
docker-compose --profile production up -d
```

### Environment Variables
Create `.env` file:
```env
BACKEND_PORT=8000
FRONTEND_PORT=3000
NGINX_PORT=80
```

### SSL/HTTPS Setup
1. Add SSL certificates to `nginx/ssl/`
2. Update `nginx/nginx.conf` for HTTPS
3. Use Let's Encrypt or custom certificates

## 🛠️ Development

### Local Development
```bash
# Backend only
cd backend && python run_server.py

# Frontend only
cd frontend && npm run dev

# Extension (no build needed)
# Load InspyGuard_extension/ directly in Chrome
```

### Rebuilding After Changes
```bash
# Rebuild specific service
docker-compose build backend
docker-compose up -d backend

# Rebuild all
docker-compose build
docker-compose up -d
```

## 📊 Performance

### Resource Usage
- **Backend:** ~50MB RAM, 1 CPU core
- **Frontend:** ~20MB RAM, 1 CPU core
- **Database:** ~10MB disk space

### Scaling
```bash
# Scale backend (multiple instances)
docker-compose up -d --scale backend=3
```

## 🔒 Security Features

- ✅ File upload monitoring
- ✅ Malicious file blocking
- ✅ Real-time threat detection
- ✅ CORS protection
- ✅ Security headers
- ✅ Input validation
- ✅ SQL injection protection

## 🎯 Testing

### Automated Tests
```bash
# Backend tests
docker-compose exec backend python -m pytest

# Frontend tests
docker-compose exec frontend npm test
```

### Manual Testing
1. Load Chrome extension
2. Visit test sites with file uploads
3. Monitor dashboard for real-time events
4. Test API endpoints via `/docs`

## 📈 Monitoring

### Health Checks
- Backend: `GET /` returns 200
- Frontend: Nginx health check
- Database: SQLite file accessible

### Metrics
- Log count and types
- Response times
- Error rates
- Resource usage

## 🆘 Troubleshooting

### Common Issues

**Docker not running:**
```bash
# Start Docker Desktop
# Or start Docker daemon
sudo systemctl start docker
```

**Port conflicts:**
```bash
# Check what's using ports
netstat -tulpn | grep :8000
netstat -tulpn | grep :3000
```

**Build failures:**
```bash
# Clean build
docker-compose down
docker system prune -f
docker-compose build --no-cache
```

**Extension not loading:**
- Check Chrome developer console
- Verify manifest.json syntax
- Ensure all files are present

### Logs Location
- **Backend logs:** `docker-compose logs backend`
- **Frontend logs:** `docker-compose logs frontend`
- **Database:** `./backend/logs.db`

## 🎉 Success!

Your complete Inspy Security system is now running with Docker! 

- 🛡️ **Chrome Extension** protecting users
- 🚀 **FastAPI Backend** processing logs
- 🎨 **React Dashboard** showing real-time data
- 🐳 **Docker** managing everything

Happy security monitoring! 🔒

