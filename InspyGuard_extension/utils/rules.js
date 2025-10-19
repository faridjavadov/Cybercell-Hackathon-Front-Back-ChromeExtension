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
        const currentDomain = window.location.hostname.toLowerCase();
        
        // Comprehensive whitelist of trusted domains that commonly use legitimate obfuscation
        const trustedDomains = [
            // Social Media & Communication
            'instagram.com', 'facebook.com', 'twitter.com', 'x.com', 'linkedin.com',
            'tiktok.com', 'snapchat.com', 'pinterest.com', 'reddit.com', 'telegram.org',
            'whatsapp.com', 'messenger.com', 'discord.com', 'slack.com', 'zoom.us',
            
            // Search & Tech Giants
            'google.com', 'youtube.com', 'gmail.com', 'googleapis.com', 'googleusercontent.com',
            'microsoft.com', 'bing.com', 'outlook.com', 'office.com', 'azure.com',
            'apple.com', 'icloud.com', 'appstore.com', 'itunes.com',
            
            // E-commerce & Services
            'amazon.com', 'amazonaws.com', 'ebay.com', 'paypal.com', 'stripe.com',
            'shopify.com', 'etsy.com', 'alibaba.com', 'walmart.com', 'target.com',
            
            // Entertainment & Media
            'netflix.com', 'spotify.com', 'youtube.com', 'twitch.tv', 'hulu.com',
            'disney.com', 'hbo.com', 'paramount.com', 'peacock.com',
            
            // Development & Tech
            'github.com', 'gitlab.com', 'stackoverflow.com', 'stackexchange.com',
            'npmjs.com', 'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
            'codepen.io', 'jsfiddle.net', 'repl.it', 'codesandbox.io',
            
            // Cloud & CDN Services
            'cloudflare.com', 'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
            'fastly.com', 'keycdn.com', 'bunnycdn.com', 'jsdelivr.net',
            
            // News & Information
            'cnn.com', 'bbc.com', 'nytimes.com', 'washingtonpost.com', 'reuters.com',
            'bloomberg.com', 'forbes.com', 'techcrunch.com', 'wired.com',
            
            // Banking & Finance
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
            'paypal.com', 'venmo.com', 'cashapp.com', 'robinhood.com',
            
            // Education
            'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
            'mit.edu', 'stanford.edu', 'harvard.edu', 'yale.edu',
            
            // Government & Official
            'gov.uk', 'usa.gov', 'irs.gov', 'ssa.gov', 'usps.com',
            
            // Additional Popular Sites
            'wikipedia.org', 'imdb.com', 'booking.com', 'expedia.com',
            'tripadvisor.com', 'yelp.com', 'craigslist.org', 'indeed.com',
            'glassdoor.com', 'monster.com', 'ziprecruiter.com'
        ];
        
        // Enhanced domain matching for subdomains and variations
        const isTrustedDomain = (domain, trustedList) => {
            // Direct match
            if (trustedList.includes(domain)) return true;
            
            // Subdomain match (e.g., www.instagram.com, api.instagram.com)
            if (trustedList.some(trusted => domain.endsWith('.' + trusted))) return true;
            
            // Parent domain match (e.g., instagram.com matches www.instagram.com)
            if (trustedList.some(trusted => domain.includes(trusted))) return true;
            
            return false;
        };
        
        // Skip scanning for trusted domains and their subdomains
        if (isTrustedDomain(currentDomain, trustedDomains)) {
            return suspicious;
        }
        
        // Only scan for highly suspicious patterns on non-trusted domains
        for (const s of Array.from(document.querySelectorAll('script'))) {
            const code = s.textContent || '';
            if (!code || code.length < 50) continue; // Skip small scripts
            
            // Skip common legitimate obfuscated scripts
            if (this.isLegitimateScript(code, s)) continue;
            
            // Only flag highly suspicious patterns
            if (this.isHighlySuspiciousCode(code)) {
                suspicious.push({
                    type: 'inline_script', 
                    reason: this.getSuspiciousReason(code), 
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
    
    isHighlySuspiciousCode(code) {
        // Pattern 1: Multiple eval calls in sequence (highly suspicious)
        const evalCount = (code.match(/eval\s*\(/g) || []).length;
        if (evalCount >= 3) return true;
        
        // Pattern 2: Heavily obfuscated with multiple encoding layers
        const encodingLayers = (code.match(/\\x[0-9A-Fa-f]{2}/g) || []).length;
        const base64Patterns = (code.match(/atob\s*\(/g) || []).length;
        if (encodingLayers >= 10 || base64Patterns >= 5) return true;
        
        // Pattern 3: Suspicious function construction patterns
        if (/new\s+Function\s*\(\s*['"`][^'"]{50,}['"`]\s*\)/g.test(code)) return true;
        
        // Pattern 4: Extremely high obfuscation ratio (>60% special chars)
        const specialCharRatio = (code.match(/[^a-zA-Z0-9\s]/g) || []).length / code.length;
        if (specialCharRatio > 0.6 && code.length > 200) return true;
        
        // Pattern 5: Multiple setTimeout with obfuscated strings
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
        // Check for common legitimate obfuscated scripts
        
        // Google Analytics / Google Tag Manager
        if (code.includes('gtag') || code.includes('ga(') || code.includes('GoogleAnalytics')) return true;
        if (code.includes('dataLayer') || code.includes('gtm')) return true;
        
        // Facebook Pixel
        if (code.includes('fbq') || code.includes('FacebookPixel')) return true;
        
        // Common analytics and tracking
        if (code.includes('mixpanel') || code.includes('amplitude') || code.includes('segment')) return true;
        if (code.includes('hotjar') || code.includes('fullstory') || code.includes('logrocket')) return true;
        
        // Ad networks and monetization
        if (code.includes('adsystem') || code.includes('doubleclick') || code.includes('googlesyndication')) return true;
        if (code.includes('amazon-adsystem') || code.includes('adsbygoogle')) return true;
        
        // CDN and performance scripts
        if (code.includes('cloudflare') || code.includes('jsdelivr') || code.includes('unpkg')) return true;
        
        // Common frameworks and libraries (often minified/obfuscated)
        if (code.includes('jquery') || code.includes('react') || code.includes('angular') || code.includes('vue')) return true;
        if (code.includes('bootstrap') || code.includes('lodash') || code.includes('moment')) return true;
        
        // Check script src for external trusted sources
        if (scriptElement.src) {
            const src = scriptElement.src.toLowerCase();
            if (src.includes('googleapis.com') || src.includes('gstatic.com')) return true;
            if (src.includes('cloudflare.com') || src.includes('jsdelivr.net')) return true;
            if (src.includes('unpkg.com') || src.includes('cdnjs.cloudflare.com')) return true;
            if (src.includes('facebook.net') || src.includes('instagram.com')) return true;
        }
        
        // Check for common legitimate patterns that might look obfuscated
        if (code.includes('webpackJsonp') || code.includes('__webpack_require__')) return true;
        if (code.includes('define(') || code.includes('require(')) return true; // AMD/CommonJS modules
        
        return false;
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