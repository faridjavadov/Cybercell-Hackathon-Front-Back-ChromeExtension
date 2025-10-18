# Inspy Security Extension

A Chrome Extension that monitors file uploads and protects against malicious content using Manifest V3.

## Features

- **File Upload Protection**: Blocks dangerous file types and large files
- **Real-time Monitoring**: Monitors all file uploads and form submissions
- **Security Logging**: Tracks all security events with timestamps
- **Clean UI**: Bootstrap 5 interface with real-time status updates
- **Backend Integration**: Sends logs to external API endpoint

## Installation

1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top right
4. Click "Load unpacked" and select the `InspyGuard_extension` folder
5. The extension icon should appear in your browser toolbar

## Usage

1. **Automatic Protection**: The extension automatically monitors all web pages for file uploads
2. **Manual Scanning**: Click the extension icon and press "Scan Now" to perform a manual scan
3. **View Logs**: Security events are displayed in the popup interface
4. **Clear Logs**: Use the "Clear" button to remove all stored security logs

## Security Rules

### Blocked File Types
- `.exe`, `.dll`, `.bat`, `.ps1`, `.jar`
- `.scr`, `.com`, `.pif`, `.cmd`, `.vbs`
- `.js`, `.jse`, `.wsf`, `.wsh`, `.msi`, `.msp`

### File Size Limits
- Maximum file size: 10 MB
- Files larger than this limit are automatically blocked

## File Structure

```
InspyGuard_extension/
├── manifest.json          # Extension configuration
├── popup.html            # Extension popup interface
├── popup.js              # Popup functionality
├── content.js            # Content script for monitoring
├── background.js         # Background service worker
├── utils/
│   └── rules.js          # Security rules and utilities
└── README.md             # This file
```

## Configuration

### Backend API
Update the `BACKEND_URL` in `background.js` to point to your logging endpoint:

```javascript
const BACKEND_URL = 'https://your-backend.com/api/logs';
```

### Security Rules
Modify `utils/rules.js` to adjust:
- Maximum file size (`MAX_FILE_SIZE`)
- Dangerous file extensions (`DANGEROUS_EXTENSIONS`)

## API Integration

The extension sends security logs to your backend in the following format:

```json
{
  "url": "https://example.com/upload",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "type": "malicious",
  "reason": "Forbidden extension"
}
```

## Future Enhancements

- **ML Anomaly Detection**: Implement machine learning models for advanced threat detection
- **VirusTotal Integration**: Add real-time virus scanning capabilities
- **User Whitelist**: Allow users to whitelist trusted domains
- **Advanced Logging**: Add more detailed security event logging
- **Custom Rules**: Allow users to define custom security rules

## Development

### Prerequisites
- Chrome browser with Developer mode enabled
- Basic knowledge of JavaScript and Chrome Extension APIs

### Testing
1. Load the extension in Developer mode
2. Visit websites with file upload functionality
3. Test with various file types and sizes
4. Monitor the popup interface for security events

## License

This project is open source and available under the MIT License.

## Support

For issues or feature requests, please create an issue in the project repository.

