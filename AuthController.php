<?php
// backend/controllers/AuthController.php

require_once __DIR__ . '/../models/User.php';
require_once __DIR__ . '/../models/SecurityLog.php';
require_once __DIR__ . '/../utils/JWTUtil.php';
require_once __DIR__ . '/../utils/PasswordHasher.php';
require_once __DIR__ . '/../utils/SecurityLogger.php';

class AuthController {
    private $db;
    private $redis;
    private $securityLogger;

    public function __construct($db) {
        $this->db = $db;
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
        $this->securityLogger = new SecurityLogger($db);
    }

    /**
     * Processa o login do usuário (SEM middleware de segurança)
     */
    public function login() {
        // Ler dados do corpo da requisição
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['email']) || !isset($input['password']) || !isset($input['fingerprint'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Email, password and fingerprint are required']);
            return;
        }

        $email = filter_var($input['email'], FILTER_SANITIZE_EMAIL);
        $password = $input['password'];
        $fingerprint = $input['fingerprint'];
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        try {
            // Buscar usuário
            $user = User::findByEmail($this->db, $email);
            
            if (!$user || !$user['is_active']) {
                $this->securityLogger->logActivity(null, $ipAddress, $userAgent, 'login_failed', 'Invalid email or inactive account');
                http_response_code(401);
                echo json_encode(['error' => 'Invalid credentials']);
                return;
            }

            // Verificar senha
            if (!PasswordHasher::verify($password, $user['password_hash'])) {
                // Incrementar tentativas falhas
                $this->handleFailedAttempt($user['id']);
                $this->securityLogger->logActivity($user['id'], $ipAddress, $userAgent, 'login_failed', 'Invalid password');
                
                http_response_code(401);
                echo json_encode(['error' => 'Invalid credentials']);
                return;
            }

            // Verificar se a conta está bloqueada por muitas tentativas
            if ($user['failed_attempts'] >= 5) {
                $this->securityLogger->logActivity($user['id'], $ipAddress, $userAgent, 'suspicious', 'Account locked due to failed attempts');
                http_response_code(423);
                echo json_encode(['error' => 'Account temporarily locked. Try again later.']);
                return;
            }

            // Atualizar fingerprint do usuário
            $this->updateUserFingerprint($user['id'], $fingerprint, $userAgent);

            // Resetar tentativas falhas
            $this->resetFailedAttempts($user['id']);

            // Atualizar último login
            $this->updateLastLogin($user['id']);

            // Gerar token JWT
            $token = $this->generateToken($user);

            // Log de login bem-sucedido
            $this->securityLogger->logActivity($user['id'], $ipAddress, $userAgent, 'login_success', 'User logged in successfully');

            // Responder com token e dados do usuário
            http_response_code(200);
            echo json_encode([
                'success' => true,
                'token' => $token,
                'user' => [
                    'id' => $user['id'],
                    'email' => $user['email'],
                    'full_name' => $user['full_name']
                ]
            ]);

        } catch (Exception $e) {
            error_log("Login error: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => 'Internal server error']);
        }
    }

    /**
     * Processa o registro de novo usuário (SEM middleware de segurança)
     */
    public function register() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['email']) || !isset($input['password']) || !isset($input['full_name'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Email, password and full name are required']);
            return;
        }

        $email = filter_var($input['email'], FILTER_SANITIZE_EMAIL);
        $password = $input['password'];
        $fullName = filter_var($input['full_name'], FILTER_SANITIZE_STRING);
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Validações
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid email format']);
            return;
        }

        if (strlen($password) < 8) {
            http_response_code(400);
            echo json_encode(['error' => 'Password must be at least 8 characters long']);
            return;
        }

        try {
            // Verificar se email já existe
            if (User::findByEmail($this->db, $email)) {
                http_response_code(409);
                echo json_encode(['error' => 'Email already registered']);
                return;
            }

            // Criar usuário
            $userId = User::create($this->db, [
                'email' => $email,
                'password' => $password,
                'full_name' => $fullName
            ]);

            if ($userId) {
                $this->securityLogger->logActivity($userId, $ipAddress, $userAgent, 'login_success', 'User registered successfully');
                
                // Gerar token automaticamente após registro
                $user = User::findById($this->db, $userId);
                $token = $this->generateToken($user);

                http_response_code(201);
                echo json_encode([
                    'success' => true,
                    'message' => 'User registered successfully',
                    'token' => $token,
                    'user' => [
                        'id' => $user['id'],
                        'email' => $user['email'],
                        'full_name' => $user['full_name']
                    ]
                ]);
            } else {
                throw new Exception('Failed to create user');
            }

        } catch (Exception $e) {
            error_log("Registration error: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => 'Internal server error']);
        }
    }

    /**
     * Processa o logout do usuário (COM middleware de segurança)
     */
    public function logout($user) {
        try {
            // Extrair token do header
            $token = $this->extractToken();
            
            if (!$token) {
                throw new Exception('Token not provided');
            }

            // Decodificar token para pegar o jti
            $decoded = JWTUtil::verify($token);
            
            // Adicionar token à blacklist
            $this->revokeToken($decoded->jti, $user->userId);
            
            // Log de logout
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
            $this->securityLogger->logActivity($user->userId, $ipAddress, $userAgent, 'logout', 'User logged out');

            http_response_code(200);
            echo json_encode(['success' => true, 'message' => 'Logged out successfully']);

        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode(['error' => 'Logout failed: ' . $e->getMessage()]);
        }
    }

    /**
     * Atualiza o token JWT (SEM middleware - usa token antigo)
     */
    public function refreshToken() {
        $token = $this->extractToken();
        
        if (!$token) {
            http_response_code(401);
            echo json_encode(['error' => 'Token not provided']);
            return;
        }

        try {
            $decoded = JWTUtil::verify($token);
            
            // Verificar se o token não foi revogado
            if ($this->isTokenRevoked($decoded->jti)) {
                http_response_code(401);
                echo json_encode(['error' => 'Token revoked']);
                return;
            }

            // Buscar dados atualizados do usuário
            $user = User::findById($this->db, $decoded->userId);
            
            if (!$user || !$user['is_active']) {
                http_response_code(401);
                echo json_encode(['error' => 'User not found or inactive']);
                return;
            }

            // Gerar novo token
            $newToken = $this->generateToken($user);

            // Revogar token antigo
            $this->revokeToken($decoded->jti, $decoded->userId);

            http_response_code(200);
            echo json_encode([
                'success' => true,
                'token' => $newToken
            ]);

        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode(['error' => 'Token refresh failed']);
        }
    }

    /**
     * Verifica se o token é válido (COM middleware de segurança)
     */
    public function verifyToken($user) {
        try {
            http_response_code(200);
            echo json_encode([
                'success' => true,
                'user' => [
                    'id' => $user->userId,
                    'email' => $user->email
                ],
                'message' => 'Token is valid'
            ]);

        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode(['error' => 'Token verification failed']);
        }
    }

    /**
     * Ação segura protegida (COM middleware de segurança)
     */
    public function secureAction($user) {
        try {
            // Log da ação segura
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
            $this->securityLogger->logActivity($user->userId, $ipAddress, $userAgent, 'login_success', 'Secure action executed');

            http_response_code(200);
            echo json_encode([
                'success' => true,
                'message' => 'Secure action completed successfully',
                'user_id' => $user->userId,
                'timestamp' => date('Y-m-d H:i:s')
            ]);

        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Secure action failed']);
        }
    }

    /**
     * Obtém logs de segurança (COM middleware de segurança)
     */
    public function getSecurityLogs($user) {
        try {
            // Parâmetros de paginação
            $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
            $perPage = isset($_GET['per_page']) ? min(100, max(1, intval($_GET['per_page']))) : 20;
            
            // Filtros
            $filters = [];
            if (isset($_GET['activity_type'])) {
                $filters['activity_type'] = $_GET['activity_type'];
            }
            if (isset($_GET['user_id'])) {
                $filters['user_id'] = intval($_GET['user_id']);
            }
            if (isset($_GET['start_date'])) {
                $filters['start_date'] = $_GET['start_date'];
            }
            if (isset($_GET['end_date'])) {
                $filters['end_date'] = $_GET['end_date'];
            }

            // Usar SecurityLog model para buscar logs
            $logs = SecurityLog::getPaginatedLogs($this->db, $page, $perPage, $filters);

            http_response_code(200);
            echo json_encode([
                'success' => true,
                'data' => $logs
            ]);

        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to retrieve security logs']);
        }
    }

    /**
     * Obtém estatísticas de segurança (COM middleware de segurança)
     */
    public function getSecurityStats($user) {
        try {
            $days = isset($_GET['days']) ? min(365, max(1, intval($_GET['days']))) : 7;
            
            // Usar SecurityLog model para buscar estatísticas
            $stats = SecurityLog::getSecurityStats($this->db, $days);

            http_response_code(200);
            echo json_encode([
                'success' => true,
                'data' => $stats
            ]);

        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to retrieve security stats']);
        }
    }

    // ============ MÉTODOS PRIVADOS ============

    private function extractToken() {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return $matches[1];
        }
        return null;
    }

    private function generateToken($user) {
        $payload = [
            'userId' => $user['id'],
            'email' => $user['email'],
            'jti' => uniqid(), // JWT ID único
            'iat' => time(),
            'exp' => time() + (60 * 60), // 1 hora
            'context' => 'web_app'
        ];

        return JWTUtil::generate($payload);
    }

    private function handleFailedAttempt($userId) {
        $stmt = $this->db->prepare(
            "UPDATE users SET failed_attempts = failed_attempts + 1, updated_at = NOW() WHERE id = ?"
        );
        $stmt->execute([$userId]);
    }

    private function resetFailedAttempts($userId) {
        $stmt = $this->db->prepare(
            "UPDATE users SET failed_attempts = 0, updated_at = NOW() WHERE id = ?"
        );
        $stmt->execute([$userId]);
    }

    private function updateLastLogin($userId) {
        $stmt = $this->db->prepare(
            "UPDATE users SET last_login = NOW(), updated_at = NOW() WHERE id = ?"
        );
        $stmt->execute([$userId]);
    }

    private function updateUserFingerprint($userId, $fingerprint, $userAgent) {
        $stmt = $this->db->prepare(
            "INSERT INTO user_security (user_id, fingerprint, user_agent, last_used) 
             VALUES (?, ?, ?, NOW()) 
             ON DUPLICATE KEY UPDATE 
             fingerprint = VALUES(fingerprint), 
             user_agent = VALUES(user_agent), 
             last_used = VALUES(last_used)"
        );
        $stmt->execute([$userId, $fingerprint, $userAgent]);
    }

    private function revokeToken($jti, $userId) {
        // Adicionar à blacklist no Redis (expiração automática)
        $this->redis->setex("revoked:{$jti}", 3600, 'revoked'); // Expira em 1 hora
        
        // Também salvar no banco para auditoria
        $stmt = $this->db->prepare(
            "INSERT INTO token_blacklist (jti, user_id, expires_at) VALUES (?, ?, FROM_UNIXTIME(?))"
        );
        $stmt->execute([$jti, $userId, time() + 3600]);
    }

    private function isTokenRevoked($jti) {
        return $this->redis->exists("revoked:{$jti}");
    }
}

?>