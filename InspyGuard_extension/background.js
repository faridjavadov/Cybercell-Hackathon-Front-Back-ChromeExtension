// Import SecurityRules (make sure it's loaded before this script)
// In manifest.json, ensure SecurityRules.js is listed before background.js

const BACKEND_URL = 'http://localhost:8000/api/logs';
const REPUTATION_URL = 'http://localhost:8000/api/reputation';

let securityLogs = [];
let urlCache = new Map();
let fileBlockCache = new Map(); // Cache for file blocking results

// ============================================
// LOGGING FUNCTIONS
// ============================================

function sendLogToBackend(log) {
    fetch(BACKEND_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(log)
    })
    .then(response => {
        if (!response.ok) {
            console.warn('Failed to send log to backend:', response.status);
        }
    })
    .catch(error => {
        console.warn('Error sending log to backend:', error);
    });
}

function storeLogLocally(log) {
    securityLogs.unshift(log);
    if (securityLogs.length > 100) {
        securityLogs = securityLogs.slice(0, 100);
    }
    
    chrome.storage.local.set({ securityLogs: securityLogs });
}

function processSecurityLog(log) {
    storeLogLocally(log);
    sendLogToBackend(log);
    
    // Notify popup if open
    chrome.runtime.sendMessage({
        action: 'updatePopup',
        log: log
    }).catch(() => {
        // Popup not open, ignore error
    });
}

// ============================================
// URL REPUTATION CHECKING
// ============================================

async function checkUrlReputation(url) {
    // Check cache first
    if (urlCache.has(url)) {
        const cached = urlCache.get(url);
        if (Date.now() - cached.timestamp < 300000) { // 5 minutes cache
            return cached.result;
        }
    }
    
    try {
        const response = await fetch(REPUTATION_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        if (response.ok) {
            const result = await response.json();
            // Cache the result
            urlCache.set(url, {
                result: result,
                timestamp: Date.now()
            });
            return result;
        }
    } catch (error) {
        console.warn('Error checking URL reputation:', error);
    }
    
    return { malicious: false, error: true };
}

function checkUrlLocally(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();
        const pathname = urlObj.pathname.toLowerCase();
        
        const maliciousPatterns = [
            /malware/i, /virus/i, /trojan/i, /phishing/i, /scam/i, /fake/i,
            /malicious/i, /suspicious/i,
            /\.exe$/i, /\.scr$/i, /\.bat$/i, /\.cmd$/i, /\.pif$/i, /\.com$/i, /\.jar$/i,
            /\/malware\//i, /\/virus\//i, /\/trojan\//i, /\/phishing\//i, /\/scam\//i, /\/fake\//i,
            /malware\./i, /virus\./i, /trojan\./i, /phishing\./i, /scam\./i, /fake\./i,
        ];
        
        for (const pattern of maliciousPatterns) {
            if (pattern.test(hostname) || pattern.test(pathname)) {
                return {
                    malicious: true,
                    reason: `Suspicious pattern detected: ${pattern.source}`
                };
            }
        }
        
        if (hostname === 'localhost' || hostname.startsWith('127.') || 
            hostname.startsWith('192.168.') || hostname.startsWith('10.')) {
            return {
                malicious: false,
                reason: 'Local/private IP address'
            };
        }
        
        const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download'];
        for (const tld of suspiciousTlds) {
            if (hostname.endsWith(tld)) {
                return {
                    malicious: true,
                    reason: `Suspicious TLD detected: ${tld}`
                };
            }
        }
        
        return { malicious: false, reason: 'No suspicious patterns detected' };
        
    } catch (error) {
        console.warn('Error in local URL detection:', error);
        return { malicious: false, reason: 'URL parsing error' };
    }
}

// ============================================
// BLOCKING PAGE HTML
// ============================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function createBlockingPageHtml(url, reason, blockType = 'url') {
    const icons = {
        url: '🚫',
        file: '📁',
        paste: '📋',
        content: '⚠️'
    };
    
    const titles = {
        url: 'ACCESS BLOCKED',
        file: 'FILE UPLOAD BLOCKED',
        paste: 'PASTE BLOCKED',
        content: 'CONTENT BLOCKED'
    };
    
    // Escape URL and reason to prevent XSS
    const escapedUrl = escapeHtml(url);
    const escapedReason = escapeHtml(reason);
    
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Inspy Security Extension - ${titles[blockType]}</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                }
                .container {
                    background: white;
                    border-radius: 20px;
                    padding: 40px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.2);
                    text-align: center;
                    max-width: 600px;
                    margin: 20px;
                    border: 3px solid #dc3545;
                }
                .icon {
                    font-size: 80px;
                    margin-bottom: 20px;
                }
                h1 {
                    color: #dc3545;
                    margin-bottom: 10px;
                    font-size: 32px;
                    font-weight: bold;
                }
                .extension-name {
                    color: #6c757d;
                    font-size: 18px;
                    margin-bottom: 20px;
                    font-weight: 500;
                }
                .url {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 10px;
                    margin: 20px 0;
                    word-break: break-all;
                    font-family: monospace;
                    color: #6c757d;
                    border: 1px solid #dee2e6;
                }
                .reason {
                    color: #dc3545;
                    font-weight: bold;
                    margin: 20px 0;
                    padding: 10px;
                    background: #f8d7da;
                    border-radius: 8px;
                    border: 1px solid #f5c6cb;
                }
                .warning-text {
                    color: #721c24;
                    margin: 20px 0;
                    font-size: 16px;
                    line-height: 1.5;
                }
                .buttons {
                    margin-top: 30px;
                }
                .back-button {
                    background: #007bff;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 8px;
                    font-size: 16px;
                    cursor: pointer;
                    margin: 0 10px;
                    transition: background 0.3s;
                }
                .back-button:hover {
                    background: #0056b3;
                }
                .home-button {
                    background: #28a745;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 8px;
                    font-size: 16px;
                    cursor: pointer;
                    margin: 0 10px;
                    transition: background 0.3s;
                }
                .home-button:hover {
                    background: #1e7e34;
                }
                .footer {
                    margin-top: 30px;
                    color: #6c757d;
                    font-size: 14px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">${icons[blockType]}</div>
                <h1>${titles[blockType]}</h1>
                <div class="extension-name">by Inspy Security Extension</div>
                <p class="warning-text">This ${blockType === 'url' ? 'website' : 'action'} has been blocked by the Inspy Security Extension to protect you from potential threats.</p>
                <div class="url">${escapedUrl}</div>
                <div class="reason">⚠️ ${escapedReason}</div>
                <p class="warning-text">The ${blockType === 'url' ? 'site' : 'content'} has been flagged as potentially malicious by our security systems. This could include phishing attempts, malware distribution, sensitive data leakage, or other security threats.</p>
                <div class="buttons">
                    <button class="back-button" onclick="history.back()">← Go Back</button>
                    <button class="home-button" onclick="window.location.href='https://www.google.com'">🏠 Go to Google</button>
                </div>
                <div class="footer">
                    <p>If you believe this is a false positive, please contact your security administrator.</p>
                    <p><strong>Inspy Security Extension v1.0.0</strong></p>
                </div>
            </div>
        </body>
        </html>
    `;
}

// ============================================
// FILE CONTENT SCANNING (using SecurityRules)
// ============================================

async function scanFileContent(fileData, fileName) {
    try {
        // Create a File object from the data
        const blob = new Blob([fileData], { type: 'text/plain' });
        const file = new File([blob], fileName, { type: 'text/plain' });
        
        // Use SecurityRules to scan (if available)
        if (typeof SecurityRules !== 'undefined') {
            const result = await SecurityRules.isFileDangerousWithContent(file);
            return result;
        }
        
        // Fallback if SecurityRules not available
        return { dangerous: false, blocked: false, reason: 'SecurityRules not available' };
        
    } catch (error) {
        console.error('Error scanning file content:', error);
        return { dangerous: false, blocked: false, reason: 'Scan error', error: true };
    }
}

// ============================================
// PASTE CONTENT SCANNING (using SecurityRules)
// ============================================

function scanPasteContent(text) {
    try {
        if (typeof SecurityRules !== 'undefined') {
            const result = SecurityRules.classifyPasteLocally(text);
            return result;
        }
        
        return { label: 'benign', blocked: false, reason: 'SecurityRules not available' };
        
    } catch (error) {
        console.error('Error scanning paste content:', error);
        return { label: 'benign', blocked: false, reason: 'Scan error', error: true };
    }
}

// ============================================
// MESSAGE HANDLERS
// ============================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    switch (request.action) {
        case 'logSecurityEvent':
            processSecurityLog(request.log);
            sendResponse({ success: true });
            break;
            
        case 'newSecurityEvent':
            chrome.runtime.sendMessage({
                action: 'updatePopup',
                log: request.log
            }).catch(() => {});
            sendResponse({ success: true });
            break;
            
        case 'getSecurityLogs':
            sendResponse({ logs: securityLogs });
            break;
            
        case 'clearSecurityLogs':
            securityLogs = [];
            chrome.storage.local.remove(['securityLogs']);
            sendResponse({ success: true });
            break;
        
        // NEW: File content scan request from content script
        case 'scanFileContent':
            (async () => {
                const result = await scanFileContent(request.fileData, request.fileName);
                
                if (result.blocked) {
                    // Log the blocked file
                    const log = {
                        url: sender.tab?.url || 'unknown',
                        timestamp: new Date().toISOString(),
                        type: 'file_blocked',
                        reason: `File upload blocked: ${result.reason}`,
                        fileName: request.fileName,
                        details: result.details
                    };
                    processSecurityLog(log);
                }
                
                sendResponse({ 
                    success: true, 
                    result: result 
                });
            })();
            return true; // Keep channel open for async response
            
        // NEW: Paste content scan request from content script
        case 'scanPasteContent':
            const result = scanPasteContent(request.text);
            
            if (result.blocked) {
                // Log the blocked paste
                const log = {
                    url: sender.tab?.url || 'unknown',
                    timestamp: new Date().toISOString(),
                    type: 'paste_blocked',
                    reason: `Paste blocked: ${result.reason}`,
                    details: result.details
                };
                processSecurityLog(log);
            }
            
            sendResponse({ 
                success: true, 
                result: result 
            });
            break;
            
        default:
            sendResponse({ success: false, error: 'Unknown action' });
    }
    
    return true;
});

// ============================================
// INITIALIZATION
// ============================================

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.get(['securityLogs'], (result) => {
        securityLogs = result.securityLogs || [];
    });
    
    console.log('Inspy Security Extension installed and initialized');
});

// ============================================
// TAB MONITORING
// ============================================

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        const log = {
            url: tab.url,
            timestamp: new Date().toISOString(),
            type: 'normal',
            reason: 'Page navigation'
        };
        
        processSecurityLog(log);
    }
});

// ============================================
// URL BLOCKING (Manifest V3 - Content Script Based)
// ============================================

const blockedUrls = new Set();

// In Manifest V3, we use webNavigation to detect navigation and let content script handle blocking
chrome.webNavigation.onBeforeNavigate.addListener(
    async (details) => {
        if (details.frameId === 0) {
            const url = details.url;
            
            // Skip internal URLs
            if (url.startsWith('chrome://') || 
                url.startsWith('chrome-extension://') || 
                url.startsWith('moz-extension://') ||
                url.startsWith('data:')) {
                return;
            }
            
            // Send message to content script to check and potentially block the URL
            try {
                await chrome.tabs.sendMessage(details.tabId, {
                    action: 'checkUrlAndBlock',
                    url: url
                });
            } catch (error) {
                // Content script not ready yet, will be handled when it loads
                console.log('Content script not ready for URL check:', url);
            }
        }
    },
    { url: [{ schemes: ['http', 'https'] }] }
);

// ============================================
// PERIODIC CLEANUP
// ============================================

// Clean up old cache entries every 10 minutes
setInterval(() => {
    const now = Date.now();
    
    // Clean URL cache
    for (const [url, data] of urlCache.entries()) {
        if (now - data.timestamp > 300000) { // 5 minutes
            urlCache.delete(url);
        }
    }
    
    // Clean file block cache
    for (const [key, data] of fileBlockCache.entries()) {
        if (now - data.timestamp > 600000) { // 10 minutes
            fileBlockCache.delete(key);
        }
    }
    
    console.log('Cache cleanup completed');
}, 600000); // Run every 10 minutes