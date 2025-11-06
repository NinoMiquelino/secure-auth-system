// frontend/js/fingerprint.js

class FingerprintGenerator {
    static async generate() {
        const components = [];
        
        // User Agent
        components.push(navigator.userAgent);
        
        // Screen properties
        components.push(screen.width + 'x' + screen.height);
        components.push(screen.colorDepth);
        
        // Timezone
        components.push(Intl.DateTimeFormat().resolvedOptions().timeZone);
        
        // Languages
        components.push(navigator.languages.join(','));
        
        // Canvas fingerprint
        components.push(await this.getCanvasFingerprint());
        
        // WebGL fingerprint
        components.push(await this.getWebGLFingerprint());
        
        // Hardware concurrency
        components.push(navigator.hardwareConcurrency);
        
        // Platform
        components.push(navigator.platform);
        
        return this.hash(components.join('|'));
    }
    
    static async getCanvasFingerprint() {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        canvas.width = 200;
        canvas.height = 50;
        
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('SecurityFingerprint', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('SecurityFingerprint', 4, 17);
        
        return canvas.toDataURL();
    }
    
    static async getWebGLFingerprint() {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        
        if (!gl) return 'no_webgl';
        
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
        const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
        
        return vendor + '|' + renderer;
    }
    
    static hash(str) {
        // Simple hash function
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(36);
    }
}