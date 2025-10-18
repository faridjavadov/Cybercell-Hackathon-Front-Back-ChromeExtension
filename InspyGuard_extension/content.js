// Inspy Security Extension - Content Script
// CSP-Safe version: Uses web_accessible_resources instead of inline scripts

(function() {
    'use strict';

    console.log('[Inspy] Content script loading...');

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
                console.log('[Inspy] SecurityRules loaded successfully');
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
    
    // Fallback SecurityRules if external loading fails
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

    console.log('[Inspy] SecurityRules loaded in content script');

    // Inject SecurityRules into page using external script (CSP-safe)
    function injectSecurityRulesCSPSafe() {
        // Create an external script tag pointing to web_accessible_resource
        const script = document.createElement('script');
        script.src = chrome.runtime.getURL('inject.js');
        script.onload = function() {
            console.log('[Inspy] ✅ inject.js loaded successfully');
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
        console.log('[Inspy] External script injected');
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
        
        console.log('[Inspy] Security event:', log);
        
        try {
            chrome.runtime.sendMessage({ action: 'logSecurityEvent', log: log });
        } catch (e) {
            console.log('[Inspy] Background not available:', e.message);
        }
    }

    function checkAndBlockFile(file) {
        console.log('[Inspy] Checking file:', file.name, file.size);
        
        if (SecurityRules.isFileDangerous(file)) {
            const reason = SecurityRules.getBlockReason(file);
            const size = SecurityRules.formatFileSize(file.size);
            
            console.log('[Inspy] 🚫 BLOCKED:', file.name, reason);
            showAlert(`Blocked: ${file.name} (${size})<br>${reason}`, 'danger');
            logEvent('malicious', `${reason}: ${file.name}`);
            
            return true;
        }
        
        console.log('[Inspy] ✅ Allowed:', file.name);
        return false;
    }

    function handleFileInput(event) {
        const input = event.target;
        if (input.type !== 'file' || !input.files || input.files.length === 0) {
            return;
        }

        console.log('[Inspy] File input detected:', input.files.length, 'file(s)');
        
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
        console.log('[Inspy] Initializing enhanced security checks...');
        
        // Start basic monitoring
        startMonitoring();
        
        // Add new security event listeners
        setupPasteMonitoring();
        setupUrlReputationCheck();
        setupJsEvasionScanning();
        
        console.log('[Inspy] ✅ Enhanced security checks initialized');
    }

    // NEW: Paste content monitoring
    function setupPasteMonitoring() {
        document.addEventListener('paste', async (e) => {
            try {
                const clipboardData = e.clipboardData || window.clipboardData;
                if (!clipboardData) return;
                
                const text = clipboardData.getData('text');
                if (!text || text.length < 10) return; // Skip very short text
                
                console.log('[Inspy] Paste detected, analyzing content...');
                
                // Check with regex patterns first (fast)
                const regexHits = SecurityRules.checkPasteWithRegex(text);
                if (regexHits.length > 0) {
                    e.preventDefault();
                    const hitTypes = regexHits.map(h => h.type).join(', ');
                    showAlert(`🚫 Paste blocked: Sensitive data detected (${hitTypes})`, 'danger');
                    logEvent('malicious', `paste_regex: ${hitTypes}`);
                    
                    // Send detailed log to backend
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
                
                // Rate limit Gemini classification to avoid API abuse
                const rateLimitKey = `paste_${window.location.hostname}`;
                if (!SecurityRules.isRateLimited(rateLimitKey, 5, 300000)) { // 5 requests per 5 minutes
                    // Check with Gemini classification (slower but more comprehensive)
                    const geminiResult = await SecurityRules.classifyPasteWithGPT(text);
                    if (geminiResult && !geminiResult.error && geminiResult.label === 'malicious') {
                        e.preventDefault();
                        showAlert(`🚫 Paste blocked: Content flagged as malicious (${geminiResult.reason})`, 'danger');
                        logEvent('malicious', `paste_gemini: ${geminiResult.reason}`);
                        
                        try {
                            await fetch('http://localhost:8000/api/logs', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify(SecurityRules.createSecurityLog(
                                    window.location.href, 
                                    'malicious', 
                                    `paste_gemini: ${geminiResult.reason}`
                                ))
                            });
                        } catch (err) {
                            console.warn('[Inspy] Failed to log Gemini classification:', err);
                        }
                        return;
                    }
                }
                
                console.log('[Inspy] ✅ Paste content approved');
                
            } catch (err) {
                console.error('[Inspy] Error in paste monitoring:', err);
            }
        });
    }

    // NEW: URL reputation checking
    function setupUrlReputationCheck() {
        // Check URL reputation on page load
        const currentUrl = window.location.href;
        const rateLimitKey = `reputation_${new URL(currentUrl).hostname}`;
        
        if (!SecurityRules.isRateLimited(rateLimitKey, 3, 3600000)) { // 3 requests per hour per domain
            SecurityRules.checkUrlReputation(currentUrl).then(result => {
                if (result && !result.error && result.malicious) {
                    showAlert(`⚠️ Warning: This site has been flagged as potentially malicious (Score: ${result.score || 'unknown'})`, 'warning');
                    logEvent('malicious', `url_reputation: score ${result.score || 'unknown'}`);
                    
                    // Send detailed log to backend
                    try {
                        fetch('http://localhost:8000/api/logs', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                url: currentUrl,
                                timestamp: new Date().toISOString(),
                                type: 'malicious',
                                reason: `url_reputation_warning: score ${result.score || 'unknown'}`
                            })
                        });
                    } catch (err) {
                        console.warn('[Inspy] Failed to log URL reputation warning:', err);
                    }
                } else {
                    // Log normal page load
                    logEvent('normal', 'Page navigation');
                }
            }).catch(err => {
                console.warn('[Inspy] URL reputation check failed:', err);
                // Still log the page load even if reputation check fails
                logEvent('normal', 'Page navigation');
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
                    console.warn('[Inspy] Suspicious JavaScript detected:', suspiciousScripts);
                    
                    // Log suspicious scripts but don't block (too aggressive)
                    suspiciousScripts.forEach(script => {
                        logEvent('suspicious', `js_evasion: ${script.type} - ${script.reason}`);
                    });
                    
                    // Show warning for high-risk patterns
                    const highRiskScripts = suspiciousScripts.filter(s => 
                        s.type === 'inline_script' && s.reason.includes('eval')
                    );
                    
                    if (highRiskScripts.length > 0) {
                        showAlert(`⚠️ Warning: Suspicious JavaScript detected on this page`, 'warning');
                    }
                }
            } catch (err) {
                console.error('[Inspy] Error in JS evasion scanning:', err);
            }
        }, 2000); // Wait 2 seconds for page to load
    }

    function startMonitoring() {
        console.log('[Inspy] Starting file monitoring...');
        
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
        console.log('[Inspy] ✅ Monitoring active');
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

    console.log('[Inspy] ✅ Content script ready');

})();