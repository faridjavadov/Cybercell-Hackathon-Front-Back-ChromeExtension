# 🛡️ InspyGuard Security Extension

A comprehensive security extension for Chrome that provides real-time protection against malicious websites, dangerous file uploads, and suspicious content.

## 🚀 Features

### 🔒 **URL Reputation Protection**
- Real-time URL reputation checking using VirusTotal and AbuseIPDB APIs
- Automatic blocking of malicious websites with custom blocking page
- Cached results for improved performance (5-minute cache)

### 📁 **File Upload Security**
- Detection and blocking of dangerous file types (.exe, .dll, .bat, etc.)
- File size validation (blocks files >10MB)
- Real-time scanning during upload attempts

### 📋 **Content Analysis**
- AI-powered paste content classification using Google Gemini
- Regex-based detection of sensitive data (API keys, SSNs, credit cards)
- Automatic blocking of malicious paste content

### 🔍 **JavaScript Evasion Detection**
- Scanning for suspicious inline scripts and event handlers
- Detection of obfuscated code patterns
- Warning system for potentially malicious JavaScript

### 📊 **Security Dashboard**
- Real-time security event logging
- Comprehensive dashboard with filtering and statistics
- Export capabilities for security reports

## 🏗️ Architecture

### **Frontend** (React Dashboard)
- Modern React application with TypeScript
- Real-time security event monitoring
- Advanced filtering and search capabilities
- Responsive design for all devices

### **Backend** (FastAPI)
- RESTful API for security operations
- Integration with external security services
- Real-time logging and event processing
- CORS-enabled for extension communication

### **Chrome Extension**
- Content script for real-time monitoring
- Background script for URL reputation checking
- Service worker for persistent security monitoring
- CSP-safe implementation

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8+
- Node.js 16+
- Chrome browser
- API keys for:
  - VirusTotal
  - Google Gemini
  - AbuseIPDB

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd InspyGuard
   ```

2. **Install Python dependencies**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. **Start the backend server**
   ```bash
   python main.py
   # Server runs on http://localhost:8000
   ```

### Frontend Setup

1. **Install dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Start the development server**
   ```bash
   npm start
   # Dashboard runs on http://localhost:3000
   ```

### Extension Setup

1. **Load the extension in Chrome**
   - Open Chrome and go to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked" and select the `InspyGuard_extension` folder

2. **Configure the extension**
   - The extension will automatically connect to the backend
   - Ensure the backend is running on `http://localhost:8000`

## 🔧 Configuration

### API Keys Setup

Create a `.env` file in the `backend` directory:

```env
# VirusTotal API Key
VT_API_KEY=your_virustotal_api_key

# Google Gemini API Key  
GEMINI_API_KEY=your_gemini_api_key

# AbuseIPDB API Key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

### Extension Permissions

The extension requires the following permissions:
- `storage` - For local data storage
- `tabs` - For tab management
- `webRequest` - For request monitoring
- `webNavigation` - For navigation blocking
- `activeTab` - For current tab access
- `scripting` - For content script injection

## 📊 Usage

### Security Dashboard
1. Open the dashboard at `http://localhost:3000`
2. View real-time security events
3. Filter by event type, date range, or reason
4. Export security reports

### Extension Protection
- **Automatic**: The extension works automatically in the background
- **URL Blocking**: Malicious URLs are blocked with a custom page
- **File Protection**: Dangerous file uploads are prevented
- **Content Scanning**: Suspicious paste content is analyzed and blocked

## 🧪 Testing

### Backend API Testing
```bash
# Test URL reputation
curl -X POST http://localhost:8000/api/reputation \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.com"}'

# Test content classification
curl -X POST http://localhost:8000/api/gpt/classify \
  -H "Content-Type: application/json" \
  -d '{"text": "Test content"}'
```

### Extension Testing
1. Navigate to a known malicious URL (e.g., `http://14.194.101.210`)
2. Verify the blocking page appears
3. Check the dashboard for logged events
4. Test file upload blocking on various websites

## 🔒 Security Features

### URL Reputation
- **VirusTotal Integration**: Checks against 70+ antivirus engines
- **AbuseIPDB Integration**: IP reputation and abuse confidence scoring
- **OR Logic**: If either service flags a URL, it's blocked
- **Thresholds**: Configurable malicious detection thresholds

### Content Analysis
- **AI Classification**: Google Gemini for intelligent content analysis
- **Regex Patterns**: Pre-defined patterns for sensitive data detection
- **Redaction**: Sensitive information is redacted before AI analysis
- **Rate Limiting**: Prevents API abuse with client-side rate limiting

### File Security
- **Extension Blocking**: Blocks dangerous file extensions
- **Size Limits**: Prevents large file uploads
- **Real-time Scanning**: Immediate detection during upload attempts

## 📈 Performance

- **Caching**: 5-minute URL reputation cache
- **Rate Limiting**: Prevents API quota exhaustion
- **Async Processing**: Non-blocking security checks
- **Optimized Queries**: Efficient database operations

## 🐛 Troubleshooting

### Extension Not Working
1. Check if the extension is loaded in Chrome
2. Verify the backend is running on `http://localhost:8000`
3. Check browser console for error messages
4. Reload the extension after making changes

### Backend Issues
1. Verify all API keys are correctly set in `.env`
2. Check if all dependencies are installed
3. Ensure port 8000 is not in use
4. Check backend logs for error messages

### API Rate Limits
- VirusTotal: 4 requests/minute (free tier)
- Gemini: 15 requests/minute (free tier)
- AbuseIPDB: 1000 requests/day (free tier)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- VirusTotal for URL reputation data
- Google Gemini for AI content classification
- AbuseIPDB for IP reputation data
- Chrome Extensions API for browser integration

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the API documentation

---

**⚠️ Security Notice**: This extension is designed for educational and research purposes. Always keep your API keys secure and never commit them to version control.
