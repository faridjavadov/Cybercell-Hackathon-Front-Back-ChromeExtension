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

    // --- NEW: URL reputation check (calls backend proxy) ---
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
            // expected: { malicious: bool, score: number, sources: {...} }
            return j;
        } catch (e) {
            console.warn('[SecurityRules] URL reputation check failed:', e);
            return { error: true };
        }
    },

    // --- NEW: JS exec / obfuscation scanner ---
    scanDocumentForJsEvasion() {
        const suspicious = [];
        
        // 1) find inline scripts
        for (const s of Array.from(document.querySelectorAll('script'))) {
            const code = s.textContent || '';
            if (!code) continue;
            
            // simple heuristics for suspicious patterns
            if (/eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`][^'"]{10,}['"`]\s*,/.test(code)) {
                suspicious.push({
                    type: 'inline_script', 
                    reason: 'eval/new Function/obfuscated string', 
                    snippet: code.slice(0, 200)
                });
            }
            
            if (/\\x[0-9A-Fa-f]{2}/.test(code) || /atob\s*\(|fromCharCode/.test(code)) {
                suspicious.push({
                    type: 'obfuscation', 
                    reason: 'hex escape or base64 usage', 
                    snippet: code.slice(0, 200)
                });
            }
            
            // Check for heavily obfuscated code (high ratio of special chars)
            const specialCharRatio = (code.match(/[^a-zA-Z0-9\s]/g) || []).length / code.length;
            if (specialCharRatio > 0.3 && code.length > 100) {
                suspicious.push({
                    type: 'obfuscation',
                    reason: 'high special character ratio',
                    snippet: code.slice(0, 200)
                });
            }
        }
        
        // 2) check attributes that can execute JS (on*)
        for (const el of Array.from(document.querySelectorAll('[onclick],[onload],[onerror],[onmouseover],[onfocus],[onblur]'))) {
            const attrs = [];
            const eventAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur'];
            
            for (const name of eventAttrs) {
                if (el.hasAttribute(name)) {
                    const value = el.getAttribute(name);
                    // Check for suspicious patterns in event handlers
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
        
        // 3) Check for dynamic script injection
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

    // --- Enhanced paste content checks (local regex heuristics only) ---
    PASTE_REGEXES: {
        // API Keys and Tokens
        API_KEY: /(?:api[_-]?key|token|secret|password)[\s:=]{0,3}[A-Za-z0-9\-\._]{16,}/i,
        AWS_ACCESS_KEY: /AKIA[0-9A-Z]{16}/,
        AWS_SECRET_KEY: /[A-Za-z0-9/+=]{40}/,
        GITHUB_TOKEN: /ghp_[A-Za-z0-9]{36}/,
        GITHUB_APP_TOKEN: /gho_[A-Za-z0-9]{36}/,
        SLACK_TOKEN: /xox[baprs]-[A-Za-z0-9-]+/,
        DISCORD_TOKEN: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/,
        STRIPE_KEY: /sk_live_[0-9a-zA-Z]{24}/,
        TWILIO_TOKEN: /[0-9a-fA-F]{32}/,
        
        // Cryptographic Keys
        PRIVATE_KEY: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
        PUBLIC_KEY: /-----BEGIN\s+(?:RSA\s+)?PUBLIC\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PUBLIC\s+KEY-----/,
        JWT: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/,
        
        // Personal Information
        SSN: /\b\d{3}-\d{2}-\d{4}\b/,
        CREDIT_CARD: /\b(?:\d{4}[-\s]?){3}\d{4}\b/,
        EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
        PHONE: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/,
        
        // Encoded Data
        LONG_BASE64: /\b(?:[A-Za-z0-9+\/]{100,}={0,2})\b/,
        HEX_ENCODED: /\b(?:[0-9a-fA-F]{2}){20,}\b/,
        
        // Database and Connection Strings
        MONGODB_URI: /mongodb(?:\+srv)?:\/\/[^\s]+/,
        POSTGRES_URI: /postgres(?:ql)?:\/\/[^\s]+/,
        MYSQL_URI: /mysql:\/\/[^\s]+/,
        REDIS_URI: /redis:\/\/[^\s]+/,
        
        // Cloud Service Keys
        GOOGLE_API_KEY: /AIza[0-9A-Za-z\\-_]{35}/,
        FIREBASE_KEY: /[A-Za-z0-9_-]{147}/,
        AZURE_KEY: /[0-9a-fA-F]{32}/,
        
        // Malicious Patterns
        SHELL_COMMANDS: /(?:rm\s+-rf|del\s+\/s|format\s+c:|shutdown|reboot|halt)/i,
        SQL_INJECTION: /(?:union\s+select|drop\s+table|delete\s+from|insert\s+into).*?(?:--|#|\/\*)/i,
        XSS_PATTERNS: /<script[^>]*>.*?<\/script>|<iframe[^>]*>.*?<\/iframe>|javascript:/i,
        PATH_TRAVERSAL: /\.\.\/(?:\.\.\/)*[^\s]*/,
        
        // Suspicious URLs
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

    // Classify severity levels for different types of sensitive data
    getSeverityLevel(type) {
        const severityMap = {
            // Critical - Immediate block
            'PRIVATE_KEY': 'critical',
            'AWS_SECRET_KEY': 'critical',
            'STRIPE_KEY': 'critical',
            'SHELL_COMMANDS': 'critical',
            'SQL_INJECTION': 'critical',
            'XSS_PATTERNS': 'critical',
            
            // High - Block with warning
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
            
            // Medium - Warn user
            'SSN': 'medium',
            'CREDIT_CARD': 'medium',
            'LONG_BASE64': 'medium',
            'HEX_ENCODED': 'medium',
            'PATH_TRAVERSAL': 'medium',
            'SUSPICIOUS_URL': 'medium',
            'IP_ADDRESS': 'medium',
            
            // Low - Informational
            'EMAIL': 'low',
            'PHONE': 'low',
            'PUBLIC_KEY': 'low'
        };
        
        return severityMap[type] || 'medium';
    },

    // Enhanced local classification without external API calls
    classifyPasteLocally(text) {
        const regexHits = this.checkPasteWithRegex(text);
        
        if (regexHits.length === 0) {
            return { label: 'benign', reason: 'No suspicious patterns detected', confidence: 0.8 };
        }
        
        // Check for critical severity items
        const criticalHits = regexHits.filter(hit => hit.severity === 'critical');
        if (criticalHits.length > 0) {
            return {
                label: 'malicious',
                reason: `Critical security risk detected: ${criticalHits.map(h => h.type).join(', ')}`,
                confidence: 0.95,
                details: criticalHits
            };
        }
        
        // Check for high severity items
        const highHits = regexHits.filter(hit => hit.severity === 'high');
        if (highHits.length > 0) {
            return {
                label: 'suspicious',
                reason: `Sensitive data detected: ${highHits.map(h => h.type).join(', ')}`,
                confidence: 0.85,
                details: highHits
            };
        }
        
        // Check for medium severity items
        const mediumHits = regexHits.filter(hit => hit.severity === 'medium');
        if (mediumHits.length > 0) {
            return {
                label: 'suspicious',
                reason: `Potentially sensitive content: ${mediumHits.map(h => h.type).join(', ')}`,
                confidence: 0.7,
                details: mediumHits
            };
        }
        
        // Low severity items
        return {
            label: 'benign',
            reason: 'Minor sensitive patterns detected but likely safe',
            confidence: 0.6,
            details: regexHits
        };
    },

    // Redact sensitive information before sending to backend
    redactSensitive(text) {
        let redacted = text;
        
        // Redact API keys and tokens
        redacted = redacted.replace(this.PASTE_REGEXES.API_KEY, '[REDACTED_API_KEY]');
        redacted = redacted.replace(this.PASTE_REGEXES.AWS_ACCESS_KEY, '[REDACTED_AWS_KEY]');
        redacted = redacted.replace(this.PASTE_REGEXES.GITHUB_TOKEN, '[REDACTED_GITHUB_TOKEN]');
        redacted = redacted.replace(this.PASTE_REGEXES.SLACK_TOKEN, '[REDACTED_SLACK_TOKEN]');
        
        // Redact private keys
        redacted = redacted.replace(this.PASTE_REGEXES.PRIVATE_KEY, '[REDACTED_PRIVATE_KEY]');
        
        // Redact JWTs (keep structure but mask content)
        redacted = redacted.replace(this.PASTE_REGEXES.JWT, (match) => {
            const parts = match.split('.');
            return parts[0] + '.[REDACTED].[REDACTED]';
        });
        
        // Redact credit cards (keep last 4 digits)
        redacted = redacted.replace(this.PASTE_REGEXES.CREDIT_CARD, (match) => {
            const digits = match.replace(/\D/g, '');
            return '****-****-****-' + digits.slice(-4);
        });
        
        // Redact SSNs
        redacted = redacted.replace(this.PASTE_REGEXES.SSN, '***-**-****');
        
        return redacted;
    },

    // SECURITY: Removed classifyPasteWithGPT to prevent data leakage
    // This function was sending potentially sensitive data to external APIs
    // Use enhanced local detection instead
    async classifyPasteWithGPT(text) {
        console.warn('[SecurityRules] classifyPasteWithGPT is disabled for security reasons');
        return { error: true, reason: 'Function disabled to prevent data leakage' };
    },

    // --- NEW: Enhanced security checks ---
    async performComprehensiveCheck(url) {
        const results = {
            url: url,
            timestamp: new Date().toISOString(),
            checks: {}
        };

        // URL reputation check
        try {
            results.checks.reputation = await this.checkUrlReputation(url);
        } catch (e) {
            results.checks.reputation = { error: true };
        }

        // JS evasion scan
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
        // Remove old requests outside the window
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