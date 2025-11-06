<?php
// backend/middleware/SecurityMiddleware.php

class SecurityMiddleware {
    private $redis;
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }
    
    public function handle($request) {
        try {
            // 1. VALIDA JWT
            $token = $this->extractToken($request);
            $decoded = JWTUtil::verify($token);
            
            // 2. VERIFICA REVOCAÇÃO (Redis)
            if ($this->isTokenRevoked($decoded->jti)) {
                throw new Exception('Token revoked');
            }
            
            // 3. VALIDA FINGERPRINT DO CLIENTE
            $clientFingerprint = $this->generateClientFingerprint($request);
            $expectedFp = $this->getUserFingerprint($decoded->userId);
            
            if ($clientFingerprint !== $expectedFp) {
                $this->logSuspiciousActivity($decoded->userId, $request['ip']);
                throw new Exception('Suspicious activity detected');
            }
            
            // 4. RATE LIMITING POR USUÁRIO
            if ($this->isRateLimited($decoded->userId)) {
                throw new Exception('Rate limit exceeded');
            }
            
            return $decoded;
            
        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode(['error' => $e->getMessage()]);
            exit;
        }
    }
    
    private function extractToken($request) {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return $matches[1];
        }
        throw new Exception('Token not provided');
    }
    
    private function isTokenRevoked($jti) {
        return $this->redis->get("revoked:{$jti}") !== false;
    }
    
    private function generateClientFingerprint($request) {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        $language = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        
        return hash('sha256', $userAgent . $ip . $accept . $language);
    }
    
    private function getUserFingerprint($userId) {
        $stmt = $this->db->prepare("SELECT fingerprint FROM user_security WHERE user_id = ?");
        $stmt->execute([$userId]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        return $result['fingerprint'] ?? null;
    }
    
    private function logSuspiciousActivity($userId, $ip) {
        $stmt = $this->db->prepare(
            "INSERT INTO security_logs (user_id, ip_address, activity_type, description) 
             VALUES (?, ?, 'suspicious_login', 'Fingerprint mismatch')"
        );
        $stmt->execute([$userId, $ip]);
    }
    
    private function isRateLimited($userId) {
        $key = "rate_limit:{$userId}:" . date('Y-m-d-H');
        $requests = $this->redis->incr($key);
        
        if ($requests == 1) {
            $this->redis->expire($key, 3600); // Expira em 1 hora
        }
        
        return $requests > 1000; // 1000 requisições por hora
    }
}
?>