# 🏗️ InspyGuard Architecture

## System Overview

InspyGuard is a multi-layered security platform consisting of:

1. **Chrome Extension** - Real-time browser protection
2. **Backend API** - Security operations and data processing
3. **AI UEBA Service** - Machine learning analytics
4. **Frontend Dashboard** - Security monitoring interface
5. **External APIs** - Third-party security services

## Component Details

### Chrome Extension
- **Content Scripts**: Monitor page activity and file uploads
- **Background Scripts**: Handle URL reputation checking
- **Service Worker**: Persistent security monitoring
- **Popup Interface**: User controls and status

### Backend API (FastAPI)
- **URL Reputation**: VirusTotal and AbuseIPDB integration
- **Content Analysis**: Google Gemini AI classification
- **Log Management**: Security event storage and retrieval
- **Real-time Streaming**: Server-sent events for live updates

### AI UEBA Service
- **Behavior Analysis**: User activity pattern detection
- **Anomaly Detection**: Machine learning-based threat identification
- **Risk Scoring**: Probability-based risk assessment
- **Feature Extraction**: Session and event analysis

### Frontend Dashboard (React)
- **Real-time Monitoring**: Live security event display
- **Filtering & Search**: Advanced log querying
- **Statistics**: Security metrics and trends
- **Export**: Report generation capabilities

## Data Flow

```
User Activity → Chrome Extension → Backend API → AI Service
                     ↓
              Security Dashboard ← Database ← External APIs
```

## Security Features

### URL Protection
- Real-time reputation checking
- Multi-source validation (VirusTotal + AbuseIPDB)
- Cached results for performance
- Automatic blocking with custom pages

### File Security
- Extension-based upload blocking
- Dangerous file type detection
- Size limit enforcement
- Real-time scanning

### Content Analysis
- AI-powered classification
- Sensitive data detection
- Regex pattern matching
- Automatic content blocking

### Behavioral Analytics
- User behavior monitoring
- Anomaly detection
- Risk scoring
- Threat prediction

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Backend** | FastAPI, Python | API server and business logic |
| **AI Service** | Python, scikit-learn | Machine learning analytics |
| **Frontend** | React, TypeScript | User interface |
| **Database** | SQLite | Data storage |
| **Extension** | JavaScript, Chrome APIs | Browser integration |
| **External** | REST APIs | Third-party services |

## Deployment Architecture

### Development
- Local services on different ports
- SQLite database
- Direct API connections

### Production
- Docker containerized services
- Load balancer (optional)
- SSL/TLS encryption
- Database backups
- Monitoring and logging

## Security Considerations

- **API Key Management**: Secure environment variable storage
- **CORS Configuration**: Controlled cross-origin access
- **Rate Limiting**: API abuse prevention
- **Data Privacy**: Sensitive information redaction
- **HTTPS**: Encrypted communication
- **Input Validation**: Request sanitization
