// inject.js
(function() {
    console.log('[Inspy inject.js] Running in page context');

    window.SecurityRules = {
        MAX_FILE_SIZE: 10 * 1024 * 1024,
        
        DANGEROUS_EXTENSIONS: [
            '.exe', '.dll', '.bat', '.ps1', '.jar', '.scr', '.com', '.pif',
            '.cmd', '.vbs', '.js', '.jse', '.wsf', '.wsh', '.msi', '.msp'
        ],
        
        checkFileSize: function(file) {
            return file.size > this.MAX_FILE_SIZE;
        },
        
        checkFileExtension: function(file) {
            const fileName = file.name.toLowerCase();
            return this.DANGEROUS_EXTENSIONS.some(ext => fileName.endsWith(ext));
        },
        
        isFileDangerous: function(file) {
            return this.checkFileSize(file) || this.checkFileExtension(file);
        },
        
        getBlockReason: function(file) {
            if (this.checkFileSize(file)) {
                return 'Large file (>10MB)';
            }
            if (this.checkFileExtension(file)) {
                return 'Forbidden extension';
            }
            return 'None';
        },
        
        formatFileSize: function(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
    };

    console.log('[Inspy inject.js] ✅ SecurityRules created:', window.SecurityRules);
    console.log('[Inspy inject.js] typeof window.SecurityRules:', typeof window.SecurityRules);

    window.dispatchEvent(new CustomEvent('INSPY_SECURITY_READY', {
        detail: { version: '1.0.0', timestamp: new Date().toISOString() }
    }));

    window.postMessage({
        type: 'SECURITY_EXTENSION_DETECTED',
        source: 'inspy-security-extension',
        timestamp: new Date().toISOString()
    }, '*');

    console.log('[Inspy inject.js] ✅ Events dispatched');
})();