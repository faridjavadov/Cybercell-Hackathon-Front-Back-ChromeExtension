document.addEventListener('DOMContentLoaded', function() {
    const scanBtn = document.getElementById('scanBtn');
    const logContainer = document.getElementById('logContainer');
    const eventCount = document.getElementById('eventCount');
    const clearLogsBtn = document.getElementById('clearLogsBtn');
    const statusIndicator = document.getElementById('statusIndicator');

    let securityLogs = [];

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

    function displayLogs() {
        if (securityLogs.length === 0) {
            logContainer.innerHTML = '<div class="text-center text-muted"><small>No security events yet</small></div>';
            return;
        }

        logContainer.innerHTML = '';
        securityLogs.slice(-10).reverse().forEach(log => {
            const logEntry = document.createElement('div');
            logEntry.className = `log-entry ${log.type === 'malicious' ? 'log-malicious' : 'log-normal'}`;
            
            const timestamp = new Date(log.timestamp).toLocaleTimeString();
            const reason = log.reason !== 'None' ? ` - ${log.reason}` : '';
            
            logEntry.innerHTML = `
                <div class="fw-bold">${log.type.toUpperCase()}</div>
                <div class="small">${timestamp}${reason}</div>
                <div class="small text-truncate" title="${log.url}">${log.url}</div>
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

    scanBtn.addEventListener('click', function() {
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Scanning...';
        
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, {action: 'scanPage'}, function(response) {
                    setTimeout(() => {
                        scanBtn.disabled = false;
                        scanBtn.innerHTML = '<i class="bi bi-shield-check"></i> Scan Now';
                        
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

    loadStoredLogs();
});

