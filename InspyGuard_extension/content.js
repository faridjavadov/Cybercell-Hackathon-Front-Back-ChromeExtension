// Inspy Security Extension - Content Script (FIXED)
// Unified blocking logic for paste and file content

(function() {
    'use strict';

    let SecurityRules = null;
    
    // Check if SecurityRules is already available globally
    if (typeof window.SecurityRules !== 'undefined') {
        SecurityRules = window.SecurityRules;
        console.log('[Inspy] SecurityRules found in global scope');
    }
    
    function loadSecurityRules() {
        try {
            
            if (typeof SecurityRules !== 'undefined' && SecurityRules !== null) {
                initializeSecurityChecks();
            } else if (typeof window.SecurityRules !== 'undefined' && window.SecurityRules !== null) {
                SecurityRules = window.SecurityRules;
                initializeSecurityChecks();
            } else {
                loadFallbackSecurityRules();
            }
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
            
            // Basic regex patterns for fallback
            PASTE_REGEXES: {
                API_KEY: /(?:api[_-]?key|token|secret|password)[\s:=]{0,3}[A-Za-z0-9\-\._]{16,}/i,
                AWS_ACCESS_KEY: /AKIA[0-9A-Z]{16}/,
                GITHUB_TOKEN: /ghp_[A-Za-z0-9]{36}/,
                PRIVATE_KEY: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
                SSN: /\b\d{3}-\d{2}-\d{4}\b/,
                CREDIT_CARD: /\b(?:\d{4}[-\s]?){3}\d{4}\b/
            },
            
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
            
            getSeverityLevel(type) {
                const critical = ['PRIVATE_KEY', 'AWS_SECRET_KEY', 'STRIPE_KEY'];
                const high = ['API_KEY', 'AWS_ACCESS_KEY', 'GITHUB_TOKEN', 'JWT'];
                
                if (critical.includes(type)) return 'critical';
                if (high.includes(type)) return 'high';
                return 'medium';
            },
            
            checkPasteWithRegex(text) {
                console.log('[Inspy] 🔍 Fallback DLP: Checking regex patterns...');
                console.log('[Inspy] 🔍 Fallback DLP: Available patterns:', Object.keys(this.PASTE_REGEXES));
                
                const hits = [];
                for (const [k, rx] of Object.entries(this.PASTE_REGEXES)) {
                    if (rx instanceof RegExp && rx.test(text)) {
                        const matches = text.match(rx);
                        if (matches) {
                            console.log('[Inspy] 🎯 Fallback DLP: Pattern matched:', k, 'Match:', matches[0]);
                            hits.push({
                                type: k,
                                snippet: matches[0].slice(0, 50),
                                severity: this.getSeverityLevel(k)
                            });
                        }
                    }
                }
                console.log('[Inspy] 🔍 Fallback DLP: Total hits:', hits.length);
                return hits;
            },
            
            classifyPasteLocally(text) {
                const hits = this.checkPasteWithRegex(text);
                
                if (hits.length === 0) {
                    return { label: 'benign', blocked: false };
                }
                
                const critical = hits.filter(h => h.severity === 'critical');
                const high = hits.filter(h => h.severity === 'high');
                
                if (critical.length > 0 || high.length > 0) {
                    return {
                        label: 'malicious',
                        blocked: true,
                        reason: `Sensitive data detected: ${hits.map(h => h.type).join(', ')}`,
                        details: hits
                    };
                }
                
                return {
                    label: 'suspicious',
                    blocked: false,
                    reason: `Potentially sensitive: ${hits.map(h => h.type).join(', ')}`,
                    details: hits
                };
            },
            
            async readFileAsText(file) {
                return new Promise((resolve, reject) => {
                    const maxSize = 1024 * 1024; // 1MB
                    const slice = file.slice(0, Math.min(file.size, maxSize));
                    const reader = new FileReader();
                    reader.onload = (e) => resolve(e.target.result);
                    reader.onerror = () => reject(new Error('Failed to read file'));
                    reader.readAsText(slice);
                });
            },
            
            async isFileDangerousWithContent(file) {
                console.log('[Inspy] 🔍 Fallback DLP: Checking file:', file.name);
                
                // Check basic properties first
                const basicDanger = this.isFileDangerous(file);
                if (basicDanger) {
                    console.log('[Inspy] 🚫 Fallback DLP: Basic danger detected');
                    return {
                        dangerous: true,
                        blocked: true,
                        reason: this.getBlockReason(file),
                        type: 'metadata'
                    };
                }
                
                // Check if it's a text file
                const textExtensions = /\.(txt|json|xml|js|sh|bash|py|rb|php|csv|log|conf|config|env|ini|yaml|yml|sql|md)$/i;
                const isTextFile = textExtensions.test(file.name);
                console.log('[Inspy] 📄 Fallback DLP: Is text file?', isTextFile, 'File name:', file.name);
                
                if (!isTextFile) {
                    console.log('[Inspy] ⏭️ Fallback DLP: Skipping non-text file');
                    return { dangerous: false, blocked: false, reason: 'Non-text file' };
                }
                
                // Scan content
                try {
                    console.log('[Inspy] 📖 Fallback DLP: Reading file content...');
                    const content = await this.readFileAsText(file);
                    console.log('[Inspy] 📖 Fallback DLP: Content length:', content.length);
                    console.log('[Inspy] 📖 Fallback DLP: Content preview:', content.substring(0, 200));
                    
                    const hits = this.checkPasteWithRegex(content);
                    console.log('[Inspy] 🔍 Fallback DLP: Regex hits:', hits);
                    
                    if (hits.length > 0) {
                        const critical = hits.filter(h => h.severity === 'critical');
                        const high = hits.filter(h => h.severity === 'high');
                        const shouldBlock = critical.length > 0 || high.length > 0;
                        
                        return {
                            dangerous: true,
                            blocked: shouldBlock,
                            reason: `DLP: ${hits.length} sensitive pattern(s) detected`,
                            type: 'content',
                            severity: critical.length > 0 ? 'critical' : (high.length > 0 ? 'high' : 'medium'),
                            details: hits.map(h => ({
                                type: h.type,
                                severity: h.severity,
                                snippet: h.snippet
                            }))
                        };
                    }
                } catch (error) {
                    console.error('[Inspy] File scan error:', error);
                }
                
                return { dangerous: false, blocked: false, reason: 'File passed checks' };
            },
            
            async checkUrlReputation(url) { return { error: true }; },
            scanDocumentForJsEvasion() { return []; },
            createSecurityLog(url, type, reason) {
                return { url, timestamp: new Date().toISOString(), type, reason };
            },
            isRateLimited() { return false; }
        };
        
        initializeSecurityChecks();
    }

    function showAlert(message, type = 'danger') {
        const wait = () => {
            if (!document.body) {
                setTimeout(wait, 50);
                return;
            }
            
            // Remove existing alerts
            document.querySelectorAll('.inspy-security-alert').forEach(el => el.remove());
            
            const alert = document.createElement('div');
            alert.className = 'inspy-security-alert';
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
                animation: slideIn 0.3s ease-out;
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
            
            // Add CSS animation
            if (!document.getElementById('inspy-styles')) {
                const style = document.createElement('style');
                style.id = 'inspy-styles';
                style.textContent = `
                    @keyframes slideIn {
                        from { transform: translateX(400px); opacity: 0; }
                        to { transform: translateX(0); opacity: 1; }
                    }
                `;
                document.head.appendChild(style);
            }
            
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
            console.warn('[Inspy] Failed to log event:', e);
        }
    }

    async function sendDlpLogToBackend(file, dangerResult) {
        try {
            const logData = {
                url: window.location.href,
                timestamp: new Date().toISOString(),
                type: 'malicious',
                reason: `${dangerResult.type}_detection: ${dangerResult.reason}`,
                file_name: file.name,
                file_size: file.size,
                file_type: file.type,
                dlp_details: {
                    severity: dangerResult.severity,
                    pattern_count: dangerResult.details ? dangerResult.details.length : 0,
                    detected_patterns: dangerResult.details ? dangerResult.details.map(d => ({
                        type: d.type,
                        severity: d.severity,
                        snippet: d.snippet
                    })) : []
                }
            };

            await fetch('http://localhost:8000/api/logs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(logData)
            });
        } catch (error) {
            console.warn('[Inspy] Failed to send DLP log:', error);
        }
    }

    // ============================================
    // FILE UPLOAD BLOCKING (CRITICAL FIX)
    // ============================================
    
    async function checkAndBlockFile(file) {
        
        if (!SecurityRules) {
            return false;
        }
        
        // CRITICAL: Use isFileDangerousWithContent which returns blocked property
        const scanResult = await SecurityRules.isFileDangerousWithContent(file);
        
        // Check if file should be BLOCKED (same logic as file size)
        if (scanResult.blocked || scanResult.dangerous) {
            const size = SecurityRules.formatFileSize(file.size);
            let alertMessage = `🚫 BLOCKED: ${file.name} (${size})<br>${scanResult.reason}`;
            
            if (scanResult.type === 'content' && scanResult.details) {
                alertMessage += `<br><strong>DLP Alert:</strong> ${scanResult.severity.toUpperCase()}<br>`;
                alertMessage += `Patterns: ${scanResult.details.slice(0, 3).map(d => d.type).join(', ')}`;
                if (scanResult.details.length > 3) {
                    alertMessage += ` +${scanResult.details.length - 3} more`;
                }
            }
            
            showAlert(alertMessage, 'danger');
            logEvent('malicious', `file_blocked: ${scanResult.reason} - ${file.name}`);
            sendDlpLogToBackend(file, scanResult);
            
            return true; // BLOCK the file
        }
        
        return false; // Allow the file
    }

    async function handleFileInput(event) {
        const input = event.target;
        
        if (input.type !== 'file' || !input.files || input.files.length === 0) {
            return;
        }

        let anyBlocked = false;
        const blockedFiles = [];
        
        // Check ALL files
        for (let i = 0; i < input.files.length; i++) {
            const file = input.files[i];
            const isBlocked = await checkAndBlockFile(file);
            
            if (isBlocked) {
                anyBlocked = true;
                blockedFiles.push(file.name);
            }
        }

        // If ANY file is blocked, PREVENT the upload completely
        if (anyBlocked) {
            // CRITICAL: Stop the event completely
            event.preventDefault();
            event.stopPropagation();
            event.stopImmediatePropagation();
            
            // Clear the file input
            input.value = '';
            if (input.files) {
                try {
                    input.files = null;
                } catch (e) {
                    // Some browsers don't allow setting files to null
                }
            }
            
            // Replace the input element to ensure it's cleared
            const newInput = input.cloneNode(false);
            input.parentNode.replaceChild(newInput, input);
            
            // Re-attach listener to new input
            newInput.addEventListener('change', handleFileInput, true);
            
            return false;
        }
        
    }

    async function handleFormSubmit(event) {
        const form = event.target;
        const fileInputs = form.querySelectorAll('input[type="file"]');
        
        for (let input of fileInputs) {
            if (input.files && input.files.length > 0) {
                for (let file of input.files) {
                    const isBlocked = await checkAndBlockFile(file);
                    
                    if (isBlocked) {
                        console.log('[Inspy] 🚫 BLOCKING form submit');
                        
                        event.preventDefault();
                        event.stopPropagation();
                        event.stopImmediatePropagation();
                        
                        // Clear the input
                        input.value = '';
                        
                        return false;
                    }
                }
            }
        }
    }

    // ============================================
    // PASTE CONTENT BLOCKING (WORKING)
    // ============================================
    
    function setupPasteMonitoring() {
        document.addEventListener('paste', async (e) => {
            try {
                const clipboardData = e.clipboardData || window.clipboardData;
                if (!clipboardData) return;
                
                const text = clipboardData.getData('text');
                if (!text || text.length < 10) return;
                
                // Use classifyPasteLocally which returns blocked property
                const result = SecurityRules.classifyPasteLocally(text);
                
                // Check blocked property (same as file content)
                if (result.blocked) {
                    
                    e.preventDefault();
                    e.stopPropagation();
                    e.stopImmediatePropagation();
                    
                    const types = result.details ? result.details.map(h => h.type).join(', ') : 'unknown';
                    showAlert(`🚫 Paste blocked: ${result.reason}`, 'danger');
                    logEvent('malicious', `paste_blocked: ${result.reason}`);
                    
                    try {
                        await fetch('http://localhost:8000/api/logs', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                url: window.location.href,
                                timestamp: new Date().toISOString(),
                                type: 'malicious',
                                reason: `paste_blocked: ${result.reason}`
                            })
                        });
                    } catch (err) {
                        console.warn('[Inspy] Failed to log paste event:', err);
                    }
                    
                    return;
                }
                
                // Warn for suspicious but not blocked
                if (result.details && result.details.length > 0 && !result.blocked) {
                    console.log('[Inspy] ⚠️ Paste warning (not blocked)');
                    showAlert(`⚠️ Warning: ${result.reason}`, 'warning');
                    logEvent('suspicious', `paste_warning: ${result.reason}`);
                }
                
            } catch (err) {
                console.error('[Inspy] Error in paste monitoring:', err);
            }
        }, true); // Use capture phase
    }
    
    function blockPage(url, reason) {
        console.log('[Inspy] 🚫 BLOCKING PAGE:', url);
        
        // Create blocking page HTML
        const blockingHtml = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Blocked - Inspy Security Extension</title>
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
                    <p class="warning-text">The site has been flagged as potentially malicious by our security systems. This could include phishing attempts, malware distribution, or other security threats.</p>
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
        
        // Replace the entire page content
        document.documentElement.innerHTML = blockingHtml;
        
        // Prevent any further navigation
        window.stop();
        
        console.log('[Inspy] ✅ Page blocked successfully');
    }

    
    async function checkUrlReputation(url) {
        try {
            console.log('[Inspy] 🔍 Checking URL reputation for:', url);
            
            const response = await fetch('http://localhost:8000/api/reputation', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });
            
            if (response.ok) {
                const result = await response.json();
                console.log('[Inspy] 📊 URL reputation result:', result);
                
                if (result.malicious) {
                    console.log('[Inspy] 🚫 Malicious URL detected - BLOCKING PAGE');
                    
                    // CRITICAL: Block the page by replacing content
                    blockPage(url, result.reason);
                    
                    showAlert(`🚫 Malicious URL: ${result.reason}`, 'danger');
                    logEvent('malicious', `url_reputation: ${result.reason}`);
                    
                    // Send reputation log to backend
                    try {
                        await fetch('http://localhost:8000/api/logs', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                url: url,
                                timestamp: new Date().toISOString(),
                                type: 'malicious',
                                reason: `url_reputation: ${result.reason}`,
                                reputation_details: {
                                    score: result.score,
                                    sources: result.sources,
                                    malicious_count: result.malicious_count
                                }
                            })
                        });
                    } catch (err) {
                        console.warn('[Inspy] Failed to log reputation event:', err);
                    }
                } else {
                    console.log('[Inspy] ✅ URL reputation: Safe');
                }
            } else {
                console.warn('[Inspy] URL reputation request failed:', response.status);
            }
        } catch (error) {
            console.warn('[Inspy] URL reputation check failed:', error);
        }
    }
    
    async function performUebaAnalysis(url) {
        try {
            console.log('[Inspy] 🔍 Performing UEBA analysis for:', url);
            
            const response = await fetch('http://localhost:8000/api/ueba', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    url: url,
                    user_behavior: {
                        timestamp: new Date().toISOString(),
                        user_agent: navigator.userAgent,
                        referrer: document.referrer
                    }
                })
            });
            
            if (response.ok) {
                const result = await response.json();
                console.log('[Inspy] 📊 UEBA result:', result);
                
                if (result.malicious) {
                    console.log('[Inspy] 🚫 UEBA detected malicious behavior - BLOCKING PAGE');
                    
                    // CRITICAL: Block the page by replacing content
                    blockPage(url, result.reason);
                    
                    showAlert(`🚫 UEBA Alert: ${result.reason}`, 'danger');
                    logEvent('malicious', `ueba_detection: ${result.reason}`);
                    
                    // Send UEBA log to backend
                    try {
                        await fetch('http://localhost:8000/api/logs', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                url: url,
                                timestamp: new Date().toISOString(),
                                type: 'malicious',
                                reason: `ueba_detection: ${result.reason}`,
                                ueba_details: {
                                    anomaly_detected: result.anomaly_detected,
                                    uninstall_predicted: result.uninstall_predicted,
                                    risk_score: result.risk_score
                                }
                            })
                        });
                    } catch (err) {
                        console.warn('[Inspy] Failed to log UEBA event:', err);
                    }
                } else {
                    console.log('[Inspy] ✅ UEBA: Normal behavior detected');
                }
            } else {
                console.warn('[Inspy] UEBA request failed:', response.status);
            }
        } catch (error) {
            console.warn('[Inspy] UEBA analysis failed:', error);
        }
    }

    
    function initializeSecurityChecks() {
        console.log('[Inspy] 🚀 Initializing security checks...');
        
        startMonitoring();
        setupPasteMonitoring();
        
        // Perform URL reputation and UEBA analysis for current URL
        const currentUrl = window.location.href;
        checkUrlReputation(currentUrl);
        performUebaAnalysis(currentUrl);
        
        console.log('[Inspy] ✅ Security checks initialized');
    }

    function startMonitoring() {
        console.log('[Inspy] 📡 Starting file upload monitoring...');
        
        // Listen for file input changes
        document.addEventListener('change', handleFileInput, true);
        document.addEventListener('input', handleFileInput, true);
        
        // Listen for form submits
        document.addEventListener('submit', handleFormSubmit, true);
        
        // Monitor for dynamically added file inputs
        const observer = new MutationObserver((mutations) => {
            for (let mutation of mutations) {
                for (let node of mutation.addedNodes) {
                    if (node.nodeType === 1 && node.querySelectorAll) {
                        const fileInputs = node.querySelectorAll('input[type="file"]');
                        if (fileInputs.length > 0) {
                            console.log('[Inspy] 🔍 Found', fileInputs.length, 'new file inputs');
                        }
                    }
                }
            }
        });
        
        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
        
        logEvent('normal', 'Extension active');
        console.log('[Inspy] ✅ Monitoring started');
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
        } else if (request.action === 'checkUrlAndBlock') {
            // Handle URL checking and blocking from background script
            (async () => {
                try {
                    const url = request.url;
                    console.log('[Inspy] 🔍 Background requested URL check for:', url);
                    
                    // Check URL reputation
                    await checkUrlReputation(url);
                    
                    // Perform UEBA analysis
                    await performUebaAnalysis(url);
                    
                    sendResponse({ success: true });
                } catch (error) {
                    console.error('[Inspy] Error in URL check:', error);
                    sendResponse({ success: false, error: error.message });
                }
            })();
            return true; // Keep channel open for async response
        }
        return true;
    });

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadSecurityRules);
    } else {
        loadSecurityRules();
    }

})();