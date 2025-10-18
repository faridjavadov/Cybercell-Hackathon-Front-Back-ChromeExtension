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

// Create blocking page HTML
function createBlockingPageHtml(url, reason) {
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Inspy Security - Blocked</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    text-align: center;
                    max-width: 500px;
                    margin: 20px;
                }
                .icon {
                    font-size: 80px;
                    margin-bottom: 20px;
                }
                h1 {
                    color: #dc3545;
                    margin-bottom: 20px;
                    font-size: 28px;
                }
                .url {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 10px;
                    margin: 20px 0;
                    word-break: break-all;
                    font-family: monospace;
                    color: #6c757d;
                }
                .reason {
                    color: #dc3545;
                    font-weight: bold;
                    margin: 20px 0;
                }
                .back-button {
                    background: #007bff;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 8px;
                    font-size: 16px;
                    cursor: pointer;
                    margin-top: 20px;
                }
                .back-button:hover {
                    background: #0056b3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">🛡️</div>
                <h1>Access Blocked</h1>
                <p>Inspy Security has blocked access to this website for your protection.</p>
                <div class="url">${url}</div>
                <div class="reason">Reason: ${reason}</div>
                <p>This site has been flagged as potentially malicious by our security systems.</p>
                <button class="back-button" onclick="history.back()">Go Back</button>
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

// Use onBeforeNavigate for better blocking control
chrome.webNavigation.onBeforeNavigate.addListener(
    async (details) => {
        if (details.frameId === 0) { // Main frame only
            const url = details.url;
            
            // Skip chrome:// and extension URLs
            if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('moz-extension://')) {
                return;
            }
            
            console.log('[Inspy] Checking URL reputation for:', url);
            
            // Check URL reputation
            const reputation = await checkUrlReputation(url);
            
            if (reputation.malicious) {
                // Block the navigation and show blocking page
                const reason = `Malicious site detected (Score: ${reputation.score || 'unknown'})`;
                
                console.log('[Inspy] 🚫 BLOCKING malicious URL:', url, reason);
                
                // Log the blocked attempt
                const log = {
                    url: url,
                    timestamp: new Date().toISOString(),
                    type: 'malicious',
                    reason: `navigation_blocked: ${reason}`
                };
                processSecurityLog(log);
                
                // Show blocking page
                showBlockingPage(details.tabId, url, reason);
                
                // Cancel the navigation
                chrome.tabs.update(details.tabId, {
                    url: `data:text/html;charset=utf-8,${encodeURIComponent(createBlockingPageHtml(url, reason))}`
                });
                
            } else {
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
        }
    },
    { url: [{ schemes: ['http', 'https'] }] }
);
