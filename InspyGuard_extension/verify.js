(function() {
    console.log('[Inspy verify.js] Checking SecurityRules...');
    console.log('[Inspy verify.js] typeof window.SecurityRules:', typeof window.SecurityRules);
    
    if (typeof window.SecurityRules !== 'undefined') {
        console.log('[Inspy verify.js] ✅ SecurityRules is available!');
        console.log('[Inspy verify.js] Properties:', Object.keys(window.SecurityRules));
        
        const testFile = { name: 'test.exe', size: 1024, type: 'application/octet-stream' };
        const isDangerous = window.SecurityRules.isFileDangerous(testFile);
        console.log('[Inspy verify.js] Test file (test.exe) is dangerous:', isDangerous);
    } else {
        console.error('[Inspy verify.js] ❌ SecurityRules is NOT available');
    }
})();