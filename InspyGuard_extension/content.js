// Inspy Security Extension - Content Script
// CSP-Safe version: Uses web_accessible_resources instead of inline scripts

(function() {
    'use strict';


    // Load SecurityRules from external file (CSP-safe)
    let SecurityRules = null;
    
    // Try to load SecurityRules from the utils file
    function loadSecurityRules() {
        try {
            // Import the rules from the utils file
            const script = document.createElement('script');
            script.src = chrome.runtime.getURL('utils/rules.js');
            script.onload = function() {
                SecurityRules = window.SecurityRules;
                initializeSecurityChecks();
            };
            script.onerror = function() {
                console.error('[Inspy] Failed to load SecurityRules, using fallback');
                loadFallbackSecurityRules();
            };
            document.head.appendChild(script);
        } catch (e) {
            console.error('[Inspy] Error loading SecurityRules:', e);
            loadFallbackSecurityRules();
        }
    }
    
    function loadFallbackSecurityRules() {
        SecurityRules = {
            MAX_FILE_SIZE: 10 * 1024 * 1024,
            DANGEROUS_EXTENSIONS: [
                '.exe', '.dll', '.bat', '.ps1', '.jar', '.scr', '.com', '.pif',
                '.cmd', '.vbs', '.js', '.jse', '.wsf', '.wsh', '.msi', '.msp'
            ],
            checkFileSize(file) { 
                return file.size > this.MAX_FILE_SIZE; 
            },
            checkFileExtension(file) {
                const fileName = file.name.toLowerCase();
                return this.DANGEROUS_EXTENSIONS.some(ext => fileName.endsWith(ext));
            },
            isFileDangerous(file) {
                return this.checkFileSize(file) || this.checkFileExtension(file);
            },
            getBlockReason(file) {
                if (this.checkFileSize(file)) return 'Large file (>10MB)';
                if (this.checkFileExtension(file)) return 'Forbidden extension';
                return 'None';
            },
            formatFileSize(bytes) {
                if (bytes === 0) return '0 Bytes';
                const k = 1024;
                const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            },
            // Basic fallback methods
            async checkUrlReputation(url) { return { error: true }; },
            scanDocumentForJsEvasion() { return []; },
            checkPasteWithRegex(text) { return []; },
            async classifyPasteWithGPT(text) { return { error: true }; }
        };
        initializeSecurityChecks();
    }


    // Inject SecurityRules into page using external script (CSP-safe)
    function injectSecurityRulesCSPSafe() {
        // Create an external script tag pointing to web_accessible_resource
        const script = document.createElement('script');
        script.src = chrome.runtime.getURL('inject.js');
        script.onload = function() {
            this.remove();
            
            // Verify injection worked
            setTimeout(() => {
                const checkScript = document.createElement('script');
                checkScript.src = chrome.runtime.getURL('verify.js');
                (document.head || document.documentElement).appendChild(checkScript);
            }, 100);
        };
        script.onerror = function() {
            console.error('[Inspy] ❌ Failed to load inject.js');
        };
        
        (document.head || document.documentElement).appendChild(script);
    }

    // Try injection
    injectSecurityRulesCSPSafe();

    // Also use custom events for communication
    window.addEventListener('message', (event) => {
        if (event.source !== window) return;
        
        if (event.data.type === 'INSPY_CHECK_FILE') {
            const file = event.data.file;
            const result = {
                dangerous: SecurityRules.isFileDangerous(file),
                reason: SecurityRules.getBlockReason(file),
                fileSize: SecurityRules.formatFileSize(file.size)
            };
            
            window.postMessage({
                type: 'INSPY_FILE_RESULT',
                id: event.data.id,
                result: result
            }, '*');
        }
    });

    function showAlert(message, type = 'danger') {
        const wait = () => {
            if (!document.body) {
                setTimeout(wait, 50);
                return;
            }
            
            const alert = document.createElement('div');
            alert.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 2147483647;
                padding: 15px 20px;
                background: ${type === 'danger' ? '#dc3545' : '#ffc107'};
                color: white;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                font-size: 14px;
                max-width: 400px;
            `;
            
            alert.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 24px;">🛡️</span>
                    <div style="flex: 1;">
                        <strong>Inspy Security</strong><br>
                        <span style="font-size: 13px;">${message}</span>
                    </div>
                    <button onclick="this.closest('div').remove()" style="
                        background: none; border: none; color: white;
                        font-size: 20px; cursor: pointer; padding: 0;
                    ">×</button>
                </div>
            `;
            
            document.body.appendChild(alert);
            setTimeout(() => alert.remove(), 5000);
        };
        wait();
    }

    function logEvent(type, reason) {
        const log = {
            url: window.location.href,
            timestamp: new Date().toISOString(),
            type: type,
            reason: reason
        };
        
        
        try {
            chrome.runtime.sendMessage({ action: 'logSecurityEvent', log: log });
        } catch (e) {
        }
    }

    function checkAndBlockFile(file) {
        
        if (SecurityRules.isFileDangerous(file)) {
            const reason = SecurityRules.getBlockReason(file);
            const size = SecurityRules.formatFileSize(file.size);
            
            showAlert(`Blocked: ${file.name} (${size})<br>${reason}`, 'danger');
            logEvent('malicious', `${reason}: ${file.name}`);
            
            return true;
        }
        
        return false;
    }

    function handleFileInput(event) {
        const input = event.target;
        if (input.type !== 'file' || !input.files || input.files.length === 0) {
            return;
        }

        
        let blocked = false;
        for (let file of input.files) {
            if (checkAndBlockFile(file)) {
                blocked = true;
            }
        }

        if (blocked) {
            event.preventDefault();
            event.stopPropagation();
            event.stopImmediatePropagation();
            input.value = '';
            return false;
        }
    }

    function handleFormSubmit(event) {
        const form = event.target;
        const fileInputs = form.querySelectorAll('input[type="file"]');
        
        for (let input of fileInputs) {
            if (input.files && input.files.length > 0) {
                for (let file of input.files) {
                    if (checkAndBlockFile(file)) {
                        event.preventDefault();
                        event.stopPropagation();
                        event.stopImmediatePropagation();
                        input.value = '';
                        return false;
                    }
                }
            }
        }
    }

    // NEW: Enhanced security monitoring functions
    function initializeSecurityChecks() {
        
        // Start basic monitoring
        startMonitoring();
        
        // Add new security event listeners
        setupPasteMonitoring();
        setupUrlReputationCheck();
        setupJsEvasionScanning();
        
    }

    // NEW: Paste content monitoring
    function setupPasteMonitoring() {
        document.addEventListener('paste', async (e) => {
            try {
                const clipboardData = e.clipboardData || window.clipboardData;
                if (!clipboardData) return;
                
                const text = clipboardData.getData('text');
                if (!text || text.length < 10) return; // Skip very short text
                
                
                // Check with regex patterns first (fast)
                const regexHits = SecurityRules.checkPasteWithRegex(text);
                if (regexHits.length > 0) {
                    e.preventDefault();
                    const hitTypes = regexHits.map(h => h.type).join(', ');
                    showAlert(`🚫 Paste blocked: Sensitive data detected (${hitTypes})`, 'danger');
                    logEvent('malicious', `paste_regex: ${hitTypes}`);
                    
                    try {
                        await fetch('http://localhost:8000/api/logs', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(SecurityRules.createSecurityLog(
                                window.location.href, 
                                'malicious', 
                                `paste_regex: ${hitTypes}`
                            ))
                        });
                    } catch (err) {
                        console.warn('[Inspy] Failed to log paste event:', err);
                    }
                    return;
                }
                
                // Enhanced local classification (no external API calls for security)
                const localResult = SecurityRules.classifyPasteLocally(text);
                if (localResult.label === 'malicious') {
                    e.preventDefault();
                    showAlert(`🚫 Paste blocked: ${localResult.reason}`, 'danger');
                    logEvent('malicious', `paste_local: ${localResult.reason}`);
                    
                    try {
                        await fetch('http://localhost:8000/api/logs', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(SecurityRules.createSecurityLog(
                                window.location.href, 
                                'malicious', 
                                `paste_local: ${localResult.reason}`
                            ))
                        });
                    } catch (err) {
                        console.warn('[Inspy] Failed to log local classification:', err);
                    }
                    return;
                } else if (localResult.label === 'suspicious') {
                    // Show warning but allow paste
                    showAlert(`⚠️ Warning: ${localResult.reason}`, 'warning');
                    logEvent('suspicious', `paste_local: ${localResult.reason}`);
                }
                
                
            } catch (err) {
                console.error('[Inspy] Error in paste monitoring:', err);
            }
        });
    }

    function checkUrlLocally(url) {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname.toLowerCase();
            const pathname = urlObj.pathname.toLowerCase();
            
            // Trusted domains that should never be flagged
            const trustedDomains = [
                'instagram.com', 'facebook.com', 'twitter.com', 'x.com', 'linkedin.com',
                'google.com', 'youtube.com', 'github.com', 'stackoverflow.com',
                'amazon.com', 'netflix.com', 'spotify.com', 'discord.com',
                'microsoft.com', 'apple.com', 'cloudflare.com', 'jsdelivr.net',
                'tiktok.com', 'snapchat.com', 'pinterest.com', 'reddit.com'
            ];
            
            // Skip local detection for trusted domains
            if (trustedDomains.some(domain => hostname.includes(domain))) {
                return { malicious: false, reason: 'Trusted domain' };
            }
            
            // Known malicious patterns
            const maliciousPatterns = [
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
                
                /malware\./i,
                /virus\./i,
                /trojan\./i,
                /phishing\./i,
                /scam\./i,
                /fake\./i,
            ];
            
            for (const pattern of maliciousPatterns) {
                if (pattern.test(hostname) || pattern.test(pathname)) {
                    return {
                        malicious: true,
                        reason: `Suspicious pattern detected: ${pattern.source}`
                    };
                }
            }
            
            // Check for suspicious IP addresses (but allow private/localhost)
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

    // Create blocking page HTML for content script
    function createBlockingPageHtml(url, reason) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Inspy Security Extension - Site Blocked</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
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

    // NEW: URL reputation checking
    function setupUrlReputationCheck() {
        // Check URL reputation on page load
        const currentUrl = window.location.href;
        
        
        // Skip local files and chrome:// URLs
        if (currentUrl.startsWith('file://') || currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://')) {
            logEvent('normal', 'Page navigation');
            return;
        }
        
        const rateLimitKey = `reputation_${new URL(currentUrl).hostname}`;
        
        if (!SecurityRules.isRateLimited(rateLimitKey, 3, 3600000)) { // 3 requests per hour per domain
            SecurityRules.checkUrlReputation(currentUrl).then(result => {
                if (result && !result.error && result.malicious) {
                    
                    // Log the malicious detection
                    logEvent('malicious', `url_reputation: score ${result.score || 'unknown'}`);
                    
                    try {
                        fetch('http://localhost:8000/api/logs', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                url: currentUrl,
                                timestamp: new Date().toISOString(),
                                type: 'malicious',
                                reason: `url_reputation_blocked: score ${result.score || 'unknown'}`
                            })
                        });
                    } catch (err) {
                        console.warn('[Inspy] Failed to log URL reputation block:', err);
                    }
                    
                    // BLOCK THE PAGE - Redirect to blocking page
                    const reason = `Malicious site detected (Score: ${result.score || 'unknown'})`;
                    const blockingPageHtml = createBlockingPageHtml(currentUrl, reason);
                    document.documentElement.innerHTML = blockingPageHtml;
                    
                } else {
                    // Log normal page load
                    logEvent('normal', 'Page navigation');
                }
            }).catch(err => {
                console.warn('[Inspy] URL reputation check failed:', err);
                
                // Fallback to local detection when API is blocked
                const localResult = checkUrlLocally(currentUrl);
                if (localResult.malicious) {
                    logEvent('malicious', `local_detection: ${localResult.reason}`);
                    
                    // Block the page with local detection
                    const reason = `Local detection: ${localResult.reason}`;
                    const blockingPageHtml = createBlockingPageHtml(currentUrl, reason);
                    document.documentElement.innerHTML = blockingPageHtml;
                } else {
                    logEvent('normal', 'Page navigation');
                }
            });
        } else {
            // Log normal page load if rate limited
            logEvent('normal', 'Page navigation');
        }
    }

    // NEW: JavaScript evasion scanning
    function setupJsEvasionScanning() {
        // Scan for suspicious JavaScript on page load
        setTimeout(() => {
            try {
                const suspiciousScripts = SecurityRules.scanDocumentForJsEvasion();
                if (suspiciousScripts.length > 0) {
                    // Only log and warn for truly high-risk patterns
                    suspiciousScripts.forEach(script => {
                        logEvent('suspicious', `js_evasion: ${script.type} - ${script.reason}`);
                    });
                    
                    // Show warning only for extremely suspicious patterns
                    const extremeRiskScripts = suspiciousScripts.filter(s => 
                        s.reason.includes('multiple eval calls') || s.reason.includes('extreme obfuscation')
                    );
                    
                    if (extremeRiskScripts.length > 0) {
                        showAlert(`⚠️ High Security Risk: Malicious JavaScript detected on this page`, 'danger');
                    }
                }
            } catch (err) {
                console.error('[Inspy] Error in JS evasion scanning:', err);
            }
        }, 2000);
    }

    function startMonitoring() {
        
        document.addEventListener('change', handleFileInput, true);
        document.addEventListener('submit', handleFormSubmit, true);
        
        new MutationObserver((mutations) => {
            for (let mutation of mutations) {
                for (let node of mutation.addedNodes) {
                    if (node.nodeType === 1 && node.querySelectorAll) {
                        node.querySelectorAll('input[type="file"]').forEach(input => {
                            input.addEventListener('change', handleFileInput, true);
                        });
                    }
                }
            }
        }).observe(document.documentElement, { childList: true, subtree: true });
        
        // Send detection message
        window.postMessage({
            type: 'SECURITY_EXTENSION_DETECTED',
            source: 'inspy-security-extension'
        }, '*');
        
        logEvent('normal', 'Extension active');
    }

    // Initialize security system
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadSecurityRules);
    } else {
        loadSecurityRules();
    }

    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'scanPage') {
            sendResponse({
                success: true,
                results: {
                    fileInputs: document.querySelectorAll('input[type="file"]').length,
                    forms: document.querySelectorAll('form').length,
                    extensionActive: true
                }
            });
        }
        return true;
    });


})();