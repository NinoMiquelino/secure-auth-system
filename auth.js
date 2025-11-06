// frontend/js/auth.js

class SecureAuth {
    constructor() {
        this.baseUrl = 'http://localhost:8000';
        this.token = localStorage.getItem('auth_token');
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.checkAuthentication();
    }
    
    setupEventListeners() {
        // Login form
        document.getElementById('loginForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });
        
        // Logout button
        document.getElementById('logoutBtn')?.addEventListener('click', () => {
            this.handleLogout();
        });
        
        // Protected action button
        document.getElementById('secureActionBtn')?.addEventListener('click', () => {
            this.performSecureAction();
        });
    }
    
    async handleLogin() {
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        
        try {
            const fingerprint = await FingerprintGenerator.generate();
            
            const response = await fetch(`${this.baseUrl}/api/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email,
                    password,
                    fingerprint
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.token = data.token;
                localStorage.setItem('auth_token', this.token);
                this.showDashboard();
                this.showNotification('Login realizado com sucesso!', 'success');
            } else {
                this.showNotification(data.error, 'error');
            }
        } catch (error) {
            this.showNotification('Erro de conexão', 'error');
        }
    }
    
    async performSecureAction() {
        try {
            const response = await fetch(`${this.baseUrl}/api/secure-action`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.status === 401) {
                this.handleLogout();
                return;
            }
            
            const data = await response.json();
            
            if (response.ok) {
                this.showNotification('Ação segura realizada!', 'success');
            } else {
                this.showNotification(data.error, 'error');
            }
        } catch (error) {
            this.showNotification('Erro de conexão', 'error');
        }
    }
    
    handleLogout() {
        if (this.token) {
            fetch(`${this.baseUrl}/api/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
        }
        
        this.token = null;
        localStorage.removeItem('auth_token');
        this.showLogin();
        this.showNotification('Logout realizado', 'info');
    }
    
    checkAuthentication() {
        if (this.token) {
            this.showDashboard();
        } else {
            this.showLogin();
        }
    }
    
    showLogin() {
        document.getElementById('loginSection').classList.remove('hidden');
        document.getElementById('dashboardSection').classList.add('hidden');
    }
    
    showDashboard() {
        document.getElementById('loginSection').classList.add('hidden');
        document.getElementById('dashboardSection').classList.remove('hidden');
    }
    
    showNotification(message, type) {
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg ${
            type === 'success' ? 'bg-green-500' : 
            type === 'error' ? 'bg-red-500' : 'bg-blue-500'
        } text-white`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new SecureAuth();
});