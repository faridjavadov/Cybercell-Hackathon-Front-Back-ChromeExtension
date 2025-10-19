const SecurityRules = {
    MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
    
    DANGEROUS_EXTENSIONS: [
        '.exe', '.dll', '.bat', '.ps1', '.jar', '.scr', '.com', '.pif',
        '.cmd', '.vbs', '.js', '.jse', '.wsf', '.wsh', '.msi', '.msp'
    ],

    // --- EXISTING FUNCTIONS ---
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
        if (this.checkFileSize(file)) {
            return 'Large file (>10MB)';
        }
        if (this.checkFileExtension(file)) {
            return 'Forbidden extension';
        }
        return 'None';
    },

    // --- DLP File Content Scanning ---
    async scanFileContent(file) {
        try {
            // Only scan text-based files for sensitive content
            const textFileTypes = [
                'text/', 'application/json', 'application/xml', 'application/javascript',
                'application/x-javascript', 'application/x-sh', 'application/x-bash',
                'text/javascript', 'text/xml', 'text/csv', 'text/plain',
                'application/x-python-code', 'application/x-ruby', 'application/x-php'
            ];
            
            const isTextFile = textFileTypes.some(type => file.type.startsWith(type)) ||
                              file.name.match(/\.(txt|json|xml|js|sh|bash|py|rb|php|csv|log|conf|config|env|ini|yaml|yml|sql|md)$/i);
            
            if (!isTextFile) {
                return { hasSensitiveData: false, blocked: false, reason: 'Non-text file, skipping content scan' };
            }
            
            // Limit file size for content scanning (max 1MB for content analysis)
            const maxContentSize = 1024 * 1024; // 1MB
            if (file.size > maxContentSize) {
                return { hasSensitiveData: false, blocked: false, reason: 'File too large for content scanning' };
            }
            
            // Read file content
            const content = await this.readFileAsText(file);
            if (!content) {
                return { hasSensitiveData: false, blocked: false, reason: 'Could not read file content' };
            }
            
            // Scan content with regex patterns
            const sensitiveHits = this.checkPasteWithRegex(content);
            
            if (sensitiveHits.length > 0) {
                // Determine overall severity and whether to block
                const hasCritical = sensitiveHits.some(hit => hit.severity === 'critical');
                const hasHigh = sensitiveHits.some(hit => hit.severity === 'high');
                const shouldBlock = hasCritical || hasHigh; // Block on critical or high severity
                
                return {
                    hasSensitiveData: true,
                    blocked: shouldBlock,
                    severity: hasCritical ? 'critical' : (hasHigh ? 'high' : 'medium'),
                    hits: sensitiveHits,
                    reason: `DLP: Detected ${sensitiveHits.length} sensitive data pattern(s) in file content`,
                    details: sensitiveHits.map(hit => ({
                        type: hit.type,
                        severity: hit.severity,
                        snippet: hit.snippet
                    }))
                };
            }
            
            return { hasSensitiveData: false, blocked: false, reason: 'No sensitive data patterns detected' };
            
        } catch (error) {
            return { 
                hasSensitiveData: false,
                blocked: false,
                reason: `Content scan failed: ${error.message}`,
                error: true 
            };
        }
    },

    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    },

    // Enhanced file danger check with content scanning - RETURNS BLOCKING DECISION
    async isFileDangerousWithContent(file) {
        // First check basic file properties
        const basicDanger = this.isFileDangerous(file);
        if (basicDanger) {
            return {
                dangerous: true,
                blocked: true, // Always block for size/extension violations
                reason: this.getBlockReason(file),
                type: 'metadata',
                details: null
            };
        }
        
        // Then check file content for sensitive data
        const contentScan = await this.scanFileContent(file);
        if (contentScan.hasSensitiveData && contentScan.blocked) {
            return {
                dangerous: true,
                blocked: true, // Block based on content
                reason: contentScan.reason,
                severity: contentScan.severity,
                type: 'content',
                details: contentScan.details
            };
        }
        
        return {
            dangerous: false,
            blocked: false,
            reason: 'File is safe',
            type: 'none',
            details: null
        };
    },
    
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    
    sanitizeUrl(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.origin + urlObj.pathname;
        } catch (e) {
            return url;
        }
    },
    
    createSecurityLog(url, type, reason) {
        return {
            url: this.sanitizeUrl(url),
            timestamp: new Date().toISOString(),
            type: type,
            reason: reason
        };
    },

    // --- URL reputation check (calls backend proxy) ---
    async checkUrlReputation(url) {
        try {
            const backendUrl = 'http://localhost:8000/api/reputation';
            const resp = await fetch(backendUrl, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ url })
            });
            if (!resp.ok) return { error: true };
            const j = await resp.json();
            return j;
        } catch (e) {
            console.warn('[SecurityRules] URL reputation check failed:', e);
            return { error: true };
        }
    },

    // --- JS exec / obfuscation scanner ---
    scanDocumentForJsEvasion() {
        const suspicious = [];
        const currentDomain = window.location.hostname.toLowerCase();
        
        const trustedDomains = [
            'instagram.com', 'facebook.com', 'twitter.com', 'x.com', 'linkedin.com',
            'tiktok.com', 'snapchat.com', 'pinterest.com', 'reddit.com', 'telegram.org',
            'whatsapp.com', 'messenger.com', 'discord.com', 'slack.com', 'zoom.us',
            'google.com', 'youtube.com', 'gmail.com', 'googleapis.com', 'googleusercontent.com',
            'microsoft.com', 'bing.com', 'outlook.com', 'office.com', 'azure.com',
            'apple.com', 'icloud.com', 'appstore.com', 'itunes.com',
            'amazon.com', 'amazonaws.com', 'ebay.com', 'paypal.com', 'stripe.com',
            'shopify.com', 'etsy.com', 'alibaba.com', 'walmart.com', 'target.com',
            'netflix.com', 'spotify.com', 'youtube.com', 'twitch.tv', 'hulu.com',
            'disney.com', 'hbo.com', 'paramount.com', 'peacock.com',
            'github.com', 'gitlab.com', 'stackoverflow.com', 'stackexchange.com',
            'npmjs.com', 'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
            'codepen.io', 'jsfiddle.net', 'repl.it', 'codesandbox.io',
            'cloudflare.com', 'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
            'fastly.com', 'keycdn.com', 'bunnycdn.com', 'jsdelivr.net',
            'cnn.com', 'bbc.com', 'nytimes.com', 'washingtonpost.com', 'reuters.com',
            'bloomberg.com', 'forbes.com', 'techcrunch.com', 'wired.com',
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
            'paypal.com', 'venmo.com', 'cashapp.com', 'robinhood.com',
            'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
            'mit.edu', 'stanford.edu', 'harvard.edu', 'yale.edu',
            'gov.uk', 'usa.gov', 'irs.gov', 'ssa.gov', 'usps.com',
            'wikipedia.org', 'imdb.com', 'booking.com', 'expedia.com',
            'tripadvisor.com', 'yelp.com', 'craigslist.org', 'indeed.com',
            'glassdoor.com', 'monster.com', 'ziprecruiter.com'
        ];
        
        const isTrustedDomain = (domain, trustedList) => {
            if (trustedList.includes(domain)) return true;
            if (trustedList.some(trusted => domain.endsWith('.' + trusted))) return true;
            if (trustedList.some(trusted => domain.includes(trusted))) return true;
            return false;
        };
        
        if (isTrustedDomain(currentDomain, trustedDomains)) {
            return suspicious;
        }
        
        for (const s of Array.from(document.querySelectorAll('script'))) {
            const code = s.textContent || '';
            if (!code || code.length < 50) continue;
            
            if (this.isLegitimateScript(code, s)) continue;
            
            if (this.isHighlySuspiciousCode(code)) {
                suspicious.push({
                    type: 'inline_script', 
                    reason: this.getSuspiciousReason(code), 
                    snippet: code.slice(0, 200)
                });
            }
        }
        
        for (const el of Array.from(document.querySelectorAll('[onclick],[onload],[onerror],[onmouseover],[onfocus],[onblur]'))) {
            const attrs = [];
            const eventAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur'];
            
            for (const name of eventAttrs) {
                if (el.hasAttribute(name)) {
                    const value = el.getAttribute(name);
                    if (/eval\s*\(|new\s+Function|javascript:/i.test(value)) {
                        attrs.push({name, value: value.slice(0, 100)});
                    }
                }
            }
            
            if (attrs.length) {
                suspicious.push({
                    type: 'dom_event_handler', 
                    reason: 'suspicious inline event handler', 
                    attrs
                });
            }
        }
        
        const scripts = Array.from(document.querySelectorAll('script[src]'));
        for (const script of scripts) {
            const src = script.src;
            if (src && (src.includes('eval') || src.includes('data:text/javascript'))) {
                suspicious.push({
                    type: 'dynamic_script',
                    reason: 'suspicious script source',
                    snippet: src
                });
            }
        }
        
        return suspicious;
    },
    
    isHighlySuspiciousCode(code) {
        const evalCount = (code.match(/eval\s*\(/g) || []).length;
        if (evalCount >= 3) return true;
        
        const encodingLayers = (code.match(/\\x[0-9A-Fa-f]{2}/g) || []).length;
        const base64Patterns = (code.match(/atob\s*\(/g) || []).length;
        if (encodingLayers >= 10 || base64Patterns >= 5) return true;
        
        if (/new\s+Function\s*\(\s*['"`][^'"]{50,}['"`]\s*\)/g.test(code)) return true;
        
        const specialCharRatio = (code.match(/[^a-zA-Z0-9\s]/g) || []).length / code.length;
        if (specialCharRatio > 0.6 && code.length > 200) return true;
        
        const setTimeoutCount = (code.match(/setTimeout\s*\(\s*['"`][^'"]{20,}['"`]/g) || []).length;
        if (setTimeoutCount >= 3) return true;
        
        return false;
    },
    
    getSuspiciousReason(code) {
        const evalCount = (code.match(/eval\s*\(/g) || []).length;
        const encodingLayers = (code.match(/\\x[0-9A-Fa-f]{2}/g) || []).length;
        const specialCharRatio = (code.match(/[^a-zA-Z0-9\s]/g) || []).length / code.length;
        
        if (evalCount >= 3) return `multiple eval calls (${evalCount})`;
        if (encodingLayers >= 10) return `heavy encoding obfuscation`;
        if (specialCharRatio > 0.6) return `extreme obfuscation (${Math.round(specialCharRatio * 100)}%)`;
        
        return 'suspicious obfuscation pattern';
    },
    
    isLegitimateScript(code, scriptElement) {
        if (code.includes('gtag') || code.includes('ga(') || code.includes('GoogleAnalytics')) return true;
        if (code.includes('dataLayer') || code.includes('gtm')) return true;
        if (code.includes('fbq') || code.includes('FacebookPixel')) return true;
        if (code.includes('mixpanel') || code.includes('amplitude') || code.includes('segment')) return true;
        if (code.includes('hotjar') || code.includes('fullstory') || code.includes('logrocket')) return true;
        if (code.includes('adsystem') || code.includes('doubleclick') || code.includes('googlesyndication')) return true;
        if (code.includes('amazon-adsystem') || code.includes('adsbygoogle')) return true;
        if (code.includes('cloudflare') || code.includes('jsdelivr') || code.includes('unpkg')) return true;
        if (code.includes('jquery') || code.includes('react') || code.includes('angular') || code.includes('vue')) return true;
        if (code.includes('bootstrap') || code.includes('lodash') || code.includes('moment')) return true;
        
        if (scriptElement.src) {
            const src = scriptElement.src.toLowerCase();
            if (src.includes('googleapis.com') || src.includes('gstatic.com')) return true;
            if (src.includes('cloudflare.com') || src.includes('jsdelivr.net')) return true;
            if (src.includes('unpkg.com') || src.includes('cdnjs.cloudflare.com')) return true;
            if (src.includes('facebook.net') || src.includes('instagram.com')) return true;
        }
        
        if (code.includes('webpackJsonp') || code.includes('__webpack_require__')) return true;
        if (code.includes('define(') || code.includes('require(')) return true;
        
        return false;
    },

    // --- Enhanced paste content checks (local regex heuristics only) ---
    PASTE_REGEXES: {
        API_KEY: /(?:api[_-]?key|token|secret|password)[\s:=]{0,3}[A-Za-z0-9\-\._]{16,}/i,
        AWS_ACCESS_KEY: /AKIA[0-9A-Z]{16}/,
        AWS_SECRET_KEY: /[A-Za-z0-9/+=]{40}/,
        GITHUB_TOKEN: /ghp_[A-Za-z0-9]{36}/,
        GITHUB_APP_TOKEN: /gho_[A-Za-z0-9]{36}/,
        SLACK_TOKEN: /xox[baprs]-[A-Za-z0-9-]+/,
        DISCORD_TOKEN: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/,
        STRIPE_KEY: /sk_live_[0-9a-zA-Z]{24}/,
        TWILIO_TOKEN: /[0-9a-fA-F]{32}/,
        PRIVATE_KEY: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
        PUBLIC_KEY: /-----BEGIN\s+(?:RSA\s+)?PUBLIC\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PUBLIC\s+KEY-----/,
        JWT: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/,
        SSN: /\b\d{3}-\d{2}-\d{4}\b/,
        CREDIT_CARD: /\b(?:\d{4}[-\s]?){3}\d{4}\b/,
        EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
        PHONE: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/,
        LONG_BASE64: /\b(?:[A-Za-z0-9+\/]{100,}={0,2})\b/,
        HEX_ENCODED: /\b(?:[0-9a-fA-F]{2}){20,}\b/,
        MONGODB_URI: /mongodb(?:\+srv)?:\/\/[^\s]+/,
        POSTGRES_URI: /postgres(?:ql)?:\/\/[^\s]+/,
        MYSQL_URI: /mysql:\/\/[^\s]+/,
        REDIS_URI: /redis:\/\/[^\s]+/,
        GOOGLE_API_KEY: /AIza[0-9A-Za-z\\-_]{35}/,
        FIREBASE_KEY: /[A-Za-z0-9_-]{147}/,
        AZURE_KEY: /[0-9a-fA-F]{32}/,
        SHELL_COMMANDS: /(?:rm\s+-rf|del\s+\/s|format\s+c:|shutdown|reboot|halt)/i,
        SQL_INJECTION: /(?:union\s+select|drop\s+table|delete\s+from|insert\s+into).*?(?:--|#|\/\*)/i,
        XSS_PATTERNS: /<script[^>]*>.*?<\/script>|<iframe[^>]*>.*?<\/iframe>|javascript:/i,
        PATH_TRAVERSAL: /\.\.\/(?:\.\.\/)*[^\s]*/,
        SUSPICIOUS_URL: /(?:bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly)\/[A-Za-z0-9]+/,
        IP_ADDRESS: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/
    },

    checkPasteWithRegex(text) {
        const hits = [];
        for (const [k, rx] of Object.entries(this.PASTE_REGEXES)) {
            if (rx instanceof RegExp && rx.test(text)) {
                const matches = text.match(rx);
                if (matches) {
                    hits.push({
                        type: k, 
                        snippet: matches[0].slice(0, 50) + (matches[0].length > 50 ? '...' : ''),
                        fullMatch: matches[0],
                        severity: this.getSeverityLevel(k)
                    });
                }
            }
        }
        return hits;
    },

    getSeverityLevel(type) {
        const severityMap = {
            'PRIVATE_KEY': 'critical',
            'AWS_SECRET_KEY': 'critical',
            'STRIPE_KEY': 'critical',
            'SHELL_COMMANDS': 'critical',
            'SQL_INJECTION': 'critical',
            'XSS_PATTERNS': 'critical',
            'API_KEY': 'high',
            'AWS_ACCESS_KEY': 'high',
            'GITHUB_TOKEN': 'high',
            'GITHUB_APP_TOKEN': 'high',
            'DISCORD_TOKEN': 'high',
            'SLACK_TOKEN': 'high',
            'GOOGLE_API_KEY': 'high',
            'FIREBASE_KEY': 'high',
            'AZURE_KEY': 'high',
            'TWILIO_TOKEN': 'high',
            'MONGODB_URI': 'high',
            'POSTGRES_URI': 'high',
            'MYSQL_URI': 'high',
            'REDIS_URI': 'high',
            'JWT': 'high',
            'SSN': 'medium',
            'CREDIT_CARD': 'medium',
            'LONG_BASE64': 'medium',
            'HEX_ENCODED': 'medium',
            'PATH_TRAVERSAL': 'medium',
            'SUSPICIOUS_URL': 'medium',
            'IP_ADDRESS': 'medium',
            'EMAIL': 'low',
            'PHONE': 'low',
            'PUBLIC_KEY': 'low'
        };
        
        return severityMap[type] || 'medium';
    },

    // Enhanced local classification - RETURNS BLOCKING DECISION
    classifyPasteLocally(text) {
        const regexHits = this.checkPasteWithRegex(text);
        
        if (regexHits.length === 0) {
            return { 
                label: 'benign', 
                blocked: false,
                reason: 'No suspicious patterns detected', 
                confidence: 0.8 
            };
        }
        
        // Check for critical severity items - BLOCK
        const criticalHits = regexHits.filter(hit => hit.severity === 'critical');
        if (criticalHits.length > 0) {
            return {
                label: 'malicious',
                blocked: true, // BLOCK critical items
                reason: `Critical security risk detected: ${criticalHits.map(h => h.type).join(', ')}`,
                confidence: 0.95,
                details: criticalHits
            };
        }
        
        // Check for high severity items - BLOCK
        const highHits = regexHits.filter(hit => hit.severity === 'high');
        if (highHits.length > 0) {
            return {
                label: 'suspicious',
                blocked: true, // BLOCK high severity items
                reason: `Sensitive data detected: ${highHits.map(h => h.type).join(', ')}`,
                confidence: 0.85,
                details: highHits
            };
        }
        
        // Check for medium severity items - WARN but don't block
        const mediumHits = regexHits.filter(hit => hit.severity === 'medium');
        if (mediumHits.length > 0) {
            return {
                label: 'suspicious',
                blocked: false, // WARN only
                reason: `Potentially sensitive content: ${mediumHits.map(h => h.type).join(', ')}`,
                confidence: 0.7,
                details: mediumHits
            };
        }
        
        // Low severity items - allow
        return {
            label: 'benign',
            blocked: false,
            reason: 'Minor sensitive patterns detected but likely safe',
            confidence: 0.6,
            details: regexHits
        };
    },

    // Redact sensitive information
    redactSensitive(text) {
        let redacted = text;
        
        redacted = redacted.replace(this.PASTE_REGEXES.API_KEY, '[REDACTED_API_KEY]');
        redacted = redacted.replace(this.PASTE_REGEXES.AWS_ACCESS_KEY, '[REDACTED_AWS_KEY]');
        redacted = redacted.replace(this.PASTE_REGEXES.GITHUB_TOKEN, '[REDACTED_GITHUB_TOKEN]');
        redacted = redacted.replace(this.PASTE_REGEXES.SLACK_TOKEN, '[REDACTED_SLACK_TOKEN]');
        redacted = redacted.replace(this.PASTE_REGEXES.PRIVATE_KEY, '[REDACTED_PRIVATE_KEY]');
        
        redacted = redacted.replace(this.PASTE_REGEXES.JWT, (match) => {
            const parts = match.split('.');
            return parts[0] + '.[REDACTED].[REDACTED]';
        });
        
        redacted = redacted.replace(this.PASTE_REGEXES.CREDIT_CARD, (match) => {
            const digits = match.replace(/\D/g, '');
            return '****-****-****-' + digits.slice(-4);
        });
        
        redacted = redacted.replace(this.PASTE_REGEXES.SSN, '***-**-****');
        
        return redacted;
    },

    // REMOVED: classifyPasteWithGPT to prevent data leakage
    async classifyPasteWithGPT(text) {
        console.warn('[SecurityRules] classifyPasteWithGPT is disabled for security reasons');
        return { error: true, blocked: false, reason: 'Function disabled to prevent data leakage' };
    },

    // --- PASTE EVENT INTERCEPTOR ---
    // Call this function to initialize paste blocking
    initializePasteProtection(options = {}) {
        const {
            onBlock = null,  // Callback when paste is blocked
            onWarn = null,   // Callback when paste triggers warning
            blockSelector = 'input, textarea, [contenteditable]' // Elements to protect
        } = options;

        document.addEventListener('paste', async (event) => {
            try {
                const clipboardData = event.clipboardData || window.clipboardData;
                const pastedText = clipboardData.getData('text');
                
                if (!pastedText || pastedText.length === 0) {
                    return; // Allow empty pastes
                }

                // Classify the pasted content
                const classification = this.classifyPasteLocally(pastedText);
                
                if (classification.blocked) {
                    // BLOCK the paste
                    event.preventDefault();
                    event.stopPropagation();
                    
                    console.warn('[SecurityRules] Paste blocked:', classification.reason);
                    
                    // Call blocking callback if provided
                    if (onBlock && typeof onBlock === 'function') {
                        onBlock({
                            reason: classification.reason,
                            details: classification.details,
                            severity: classification.label
                        });
                    }
                    
                    // Show alert to user
                    alert(`Paste blocked!\n\n${classification.reason}\n\nThis content contains sensitive information that cannot be pasted for security reasons.`);
                    
                } else if (classification.details && classification.details.length > 0) {
                    // WARN but allow paste
                    console.warn('[SecurityRules] Paste warning:', classification.reason);
                    
                    if (onWarn && typeof onWarn === 'function') {
                        onWarn({
                            reason: classification.reason,
                            details: classification.details,
                            severity: classification.label
                        });
                    }
                }
                
            } catch (error) {
                console.error('[SecurityRules] Error in paste protection:', error);
            }
        }, true); // Use capture phase to intercept early

        console.log('[SecurityRules] Paste protection initialized');
    },

    // --- Enhanced security checks ---
    async performComprehensiveCheck(url) {
        const results = {
            url: url,
            timestamp: new Date().toISOString(),
            checks: {}
        };

        try {
            results.checks.reputation = await this.checkUrlReputation(url);
        } catch (e) {
            results.checks.reputation = { error: true };
        }

        try {
            results.checks.jsEvasion = this.scanDocumentForJsEvasion();
        } catch (e) {
            results.checks.jsEvasion = { error: true };
        }

        return results;
    },

    // Rate limiting for API calls
    _rateLimitStore: new Map(),
    
    isRateLimited(key, maxRequests = 10, windowMs = 60000) {
        const now = Date.now();
        const windowStart = now - windowMs;
        
        if (!this._rateLimitStore.has(key)) {
            this._rateLimitStore.set(key, []);
        }
        
        const requests = this._rateLimitStore.get(key);
        const validRequests = requests.filter(time => time > windowStart);
        
        if (validRequests.length >= maxRequests) {
            return true;
        }
        
        validRequests.push(now);
        this._rateLimitStore.set(key, validRequests);
        return false;
    }
};

// Support both CommonJS (for Node.js/backend) and browser/Chrome extension environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityRules;
}

// Make available in window context for Chrome extension
if (typeof window !== 'undefined') {
    window.SecurityRules = SecurityRules;
}