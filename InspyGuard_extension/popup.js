document.addEventListener('DOMContentLoaded', function() {
    const scanBtn = document.getElementById('scanBtn');
    const scanIcon = document.getElementById('scanIcon');
    const scanText = document.getElementById('scanText');
    const logContainer = document.getElementById('logContainer');
    const eventCount = document.getElementById('eventCount');
    const clearLogsBtn = document.getElementById('clearLogsBtn');
    const statusIndicator = document.getElementById('statusIndicator');
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.getElementById('themeIcon');

    let securityLogs = [];
    let isDarkMode = false;

    function updateStatusIndicator() {
        const maliciousCount = securityLogs.filter(log => log.type === 'malicious').length;
        if (maliciousCount > 0) {
            statusIndicator.className = 'status-indicator status-danger';
        } else if (securityLogs.length > 0) {
            statusIndicator.className = 'status-indicator status-warning';
        } else {
            statusIndicator.className = 'status-indicator status-active';
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function displayLogs() {
        if (securityLogs.length === 0) {
            logContainer.innerHTML = `
                <div class="empty-state">
                    <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">🛡️</div>
                    <div>No security events detected</div>
                    <div style="font-size: 0.625rem; margin-top: 0.25rem; opacity: 0.7;">Start browsing to see monitoring activity</div>
                </div>
            `;
            return;
        }

        logContainer.innerHTML = '';
        securityLogs.slice(-10).reverse().forEach(log => {
            const logEntry = document.createElement('div');
            
            // Determine log class based on type
            let logClass = 'log-normal';
            if (log.type === 'malicious') {
                logClass = 'log-malicious';
            } else if (log.type === 'suspicious') {
                logClass = 'log-suspicious';
            }
            
            logEntry.className = `log-entry ${logClass}`;
            
            const timestamp = new Date(log.timestamp).toLocaleTimeString();
            const reason = log.reason !== 'None' ? log.reason : '';
            
            // Escape all user data to prevent XSS
            const escapedUrl = escapeHtml(log.url);
            const escapedReason = escapeHtml(reason);
            const escapedType = escapeHtml(log.type.toUpperCase());
            
            logEntry.innerHTML = `
                <div class="log-type">${escapedType}</div>
                <div class="log-time">${timestamp}</div>
                <div class="log-url" title="${escapedUrl}">${escapedUrl}</div>
                ${reason ? `<div class="log-reason">${escapedReason}</div>` : ''}
            `;
            
            logContainer.appendChild(logEntry);
        });
    }

    function updateEventCount() {
        eventCount.textContent = securityLogs.length;
    }

    function loadStoredLogs() {
        chrome.storage.local.get(['securityLogs'], function(result) {
            securityLogs = result.securityLogs || [];
            displayLogs();
            updateEventCount();
            updateStatusIndicator();
        });
    }

    function saveLogs() {
        chrome.storage.local.set({ securityLogs: securityLogs });
    }

    function addLog(log) {
        securityLogs.unshift(log);
        if (securityLogs.length > 50) {
            securityLogs = securityLogs.slice(0, 50);
        }
        saveLogs();
        displayLogs();
        updateEventCount();
        updateStatusIndicator();
    }

    // Dark mode functionality
    function toggleTheme() {
        isDarkMode = !isDarkMode;
        document.documentElement.classList.toggle('dark', isDarkMode);
        themeIcon.textContent = isDarkMode ? '☀️' : '🌙';
        
        // Save theme preference
        chrome.storage.local.set({ isDarkMode: isDarkMode });
    }

    function loadTheme() {
        chrome.storage.local.get(['isDarkMode'], function(result) {
            isDarkMode = result.isDarkMode || false;
            document.documentElement.classList.toggle('dark', isDarkMode);
            themeIcon.textContent = isDarkMode ? '☀️' : '🌙';
        });
    }

    // Theme toggle event listener
    themeToggle.addEventListener('click', toggleTheme);

    scanBtn.addEventListener('click', function() {
        scanBtn.disabled = true;
        scanIcon.innerHTML = '<div class="spinner"></div>';
        scanText.textContent = 'Scanning...';
        
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, {action: 'scanPage'}, function(response) {
                    setTimeout(() => {
                        scanBtn.disabled = false;
                        scanIcon.textContent = '🔍';
                        scanText.textContent = 'Scan Current Page';
                        
                        if (response && response.success) {
                            const scanLog = {
                                url: tabs[0].url,
                                timestamp: new Date().toISOString(),
                                type: 'normal',
                                reason: 'Manual scan completed'
                            };
                            addLog(scanLog);
                        }
                    }, 1000);
                });
            }
        });
    });

    clearLogsBtn.addEventListener('click', function() {
        securityLogs = [];
        saveLogs();
        displayLogs();
        updateEventCount();
        updateStatusIndicator();
    });

    chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
        if (request.action === 'newSecurityEvent') {
            addLog(request.log);
        }
    });

    // Initialize
    loadTheme();
    loadStoredLogs();
});

