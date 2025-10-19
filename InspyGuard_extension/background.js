const BACKEND_URL = 'http://localhost:8000/api/logs';
const REPUTATION_URL = 'http://localhost:8000/api/reputation';

let securityLogs = [];
let urlCache = new Map(); // Cache for URL reputation results

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
}

// Check URL reputation with caching
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

// Local URL detection for fallback when API is unavailable
function checkUrlLocally(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();
        const pathname = urlObj.pathname.toLowerCase();
        
        // Known malicious patterns
        const maliciousPatterns = [
            // Common malware domains
            /malware/i,
            /virus/i,
            /trojan/i,
            /phishing/i,
            /scam/i,
            /fake/i,
            /malicious/i,
            /suspicious/i,
            
            // Common malicious file extensions
            /\.exe$/i,
            /\.scr$/i,
            /\.bat$/i,
            /\.cmd$/i,
            /\.pif$/i,
            /\.com$/i,
            /\.jar$/i,
            
            // Suspicious paths
            /\/malware\//i,
            /\/virus\//i,
            /\/trojan\//i,
            /\/phishing\//i,
            /\/scam\//i,
            /\/fake\//i,
            
            // Common malicious subdomains
            /malware\./i,
            /virus\./i,
            /trojan\./i,
            /phishing\./i,
            /scam\./i,
            /fake\./i,
        ];
        
        // Check hostname and pathname against patterns
        for (const pattern of maliciousPatterns) {
            if (pattern.test(hostname) || pattern.test(pathname)) {
                return {
                    malicious: true,
                    reason: `Suspicious pattern detected: ${pattern.source}`
                };
            }
        }
        
        // Check for suspicious IP addresses (private/localhost)
        if (hostname === 'localhost' || hostname.startsWith('127.') || hostname.startsWith('192.168.') || hostname.startsWith('10.')) {
            return {
                malicious: false,
                reason: 'Local/private IP address'
            };
        }
        
        // Check for suspicious TLDs
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

// Create blocking page HTML
function createBlockingPageHtml(url, reason) {
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Inspy Security Extension - Site Blocked</title>
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
                <div class="icon">🚫</div>
                <h1>ACCESS BLOCKED</h1>
                <div class="extension-name">by Inspy Security Extension</div>
                <p class="warning-text">This website has been blocked by the Inspy Security Extension to protect you from potential threats.</p>
                <div class="url">${url}</div>
                <div class="reason">⚠️ ${reason}</div>
                <p class="warning-text">The site you're trying to visit has been flagged as potentially malicious by our security systems. This could include phishing attempts, malware distribution, or other security threats.</p>
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

// Show blocking page
function showBlockingPage(tabId, url, reason) {
    chrome.tabs.update(tabId, {
        url: `data:text/html;charset=utf-8,${encodeURIComponent(createBlockingPageHtml(url, reason))}`
    });
}

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
            });
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
            
        default:
            sendResponse({ success: false, error: 'Unknown action' });
    }
    
    return true;
});

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.get(['securityLogs'], (result) => {
        securityLogs = result.securityLogs || [];
    });
});

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

// Store blocked URLs to prevent navigation
const blockedUrls = new Set();

// Enhanced webRequest blocking for main frame requests
chrome.webRequest.onBeforeRequest.addListener(
    async (details) => {
        // Only block main frame requests
        if (details.type === 'main_frame') {
            const url = details.url;
            
            // Skip chrome:// and extension URLs
            if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('moz-extension://')) {
                return;
            }
            
            console.log('[Inspy] Checking URL reputation for:', url);
            
            // Check URL reputation
            const reputation = await checkUrlReputation(url);
            
            console.log('[Inspy] Reputation check result for', url, ':', reputation);
            
            if (reputation.malicious) {
                // Block the navigation
                const reason = `Malicious site detected (Score: ${reputation.score || 'unknown'})`;
                
                console.log('[Inspy] 🚫 BLOCKING malicious URL:', url, reason);
                
                // Add to blocked URLs set
                blockedUrls.add(url);
                
                // Log the blocked attempt
                const log = {
                    url: url,
                    timestamp: new Date().toISOString(),
                    type: 'malicious',
                    reason: `navigation_blocked: ${reason}`
                };
                processSecurityLog(log);
                
                // Redirect to blocking page
                return {
                    redirectUrl: `data:text/html;charset=utf-8,${encodeURIComponent(createBlockingPageHtml(url, reason))}`
                };
                
            } else if (reputation.error) {
                // If reputation check failed, use local fallback detection
                console.log('[Inspy] Reputation check failed, using local detection for:', url);
                const localResult = checkUrlLocally(url);
                
                if (localResult.malicious) {
                    const reason = `Local detection: ${localResult.reason}`;
                    console.log('[Inspy] 🚫 BLOCKING URL via local detection:', url, reason);
                    
                    blockedUrls.add(url);
                    const log = {
                        url: url,
                        timestamp: new Date().toISOString(),
                        type: 'malicious',
                        reason: `local_detection: ${localResult.reason}`
                    };
                    processSecurityLog(log);
                    
                    return {
                        redirectUrl: `data:text/html;charset=utf-8,${encodeURIComponent(createBlockingPageHtml(url, reason))}`
                    };
                }
            }
            
            // Log normal navigation
            const log = {
                url: url,
                timestamp: new Date().toISOString(),
                type: 'normal',
                reason: 'Navigation request'
            };
            processSecurityLog(log);
            console.log('[Inspy] ✅ Allowing navigation to:', url);
        }
    },
    { urls: ['<all_urls>'] },
    ['blocking']
);

// Fallback: Use onBeforeNavigate for additional blocking control
chrome.webNavigation.onBeforeNavigate.addListener(
    async (details) => {
        if (details.frameId === 0) { // Main frame only
            const url = details.url;
            
            // Skip chrome:// and extension URLs
            if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('moz-extension://')) {
                return;
            }
            
            // If URL is in blocked set, redirect to blocking page
            if (blockedUrls.has(url)) {
                console.log('[Inspy] 🚫 Redirecting blocked URL:', url);
                
                // Redirect to blocking page
                chrome.tabs.update(details.tabId, {
                    url: `data:text/html;charset=utf-8,${encodeURIComponent(createBlockingPageHtml(url, 'Site blocked by Inspy Security Extension'))}`
                });
            }
        }
    },
    { url: [{ schemes: ['http', 'https'] }] }
);
