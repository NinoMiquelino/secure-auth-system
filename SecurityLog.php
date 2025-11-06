<?php
// backend/models/SecurityLog.php

class SecurityLog {
    
    /**
     * Registrar uma atividade de segurança
     */
    public static function log($db, $userId, $ipAddress, $userAgent, $activityType, $description = '') {
        $stmt = $db->prepare(
            "INSERT INTO security_logs (user_id, ip_address, user_agent, activity_type, description) 
             VALUES (?, ?, ?, ?, ?)"
        );
        
        return $stmt->execute([
            $userId,
            $ipAddress,
            $userAgent,
            $activityType,
            $description
        ]);
    }
    
    /**
     * Buscar logs por usuário
     */
    public static function findByUserId($db, $userId, $limit = 50, $offset = 0) {
        $stmt = $db->prepare(
            "SELECT * FROM security_logs 
             WHERE user_id = ? 
             ORDER BY created_at DESC 
             LIMIT ? OFFSET ?"
        );
        
        $stmt->execute([$userId, $limit, $offset]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Buscar logs por tipo de atividade
     */
    public static function findByActivityType($db, $activityType, $limit = 50, $offset = 0) {
        $stmt = $db->prepare(
            "SELECT sl.*, u.email, u.full_name 
             FROM security_logs sl
             LEFT JOIN users u ON sl.user_id = u.id
             WHERE activity_type = ? 
             ORDER BY created_at DESC 
             LIMIT ? OFFSET ?"
        );
        
        $stmt->execute([$activityType, $limit, $offset]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Buscar logs por período
     */
    public static function findByDateRange($db, $startDate, $endDate, $limit = 100) {
        $stmt = $db->prepare(
            "SELECT sl.*, u.email, u.full_name 
             FROM security_logs sl
             LEFT JOIN users u ON sl.user_id = u.id
             WHERE created_at BETWEEN ? AND ? 
             ORDER BY created_at DESC 
             LIMIT ?"
        );
        
        $stmt->execute([$startDate, $endDate, $limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Buscar atividades suspeitas
     */
    public static function findSuspiciousActivities($db, $limit = 50) {
        $stmt = $db->prepare(
            "SELECT sl.*, u.email, u.full_name 
             FROM security_logs sl
             LEFT JOIN users u ON sl.user_id = u.id
             WHERE activity_type IN ('suspicious', 'login_failed', 'rate_limit_exceeded', 'token_revoked')
             ORDER BY created_at DESC 
             LIMIT ?"
        );
        
        $stmt->execute([$limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Contar tentativas de login falhas por IP
     */
    public static function countFailedAttemptsByIp($db, $ipAddress, $timeWindow = '1 HOUR') {
        $stmt = $db->prepare(
            "SELECT COUNT(*) as attempt_count 
             FROM security_logs 
             WHERE ip_address = ? 
             AND activity_type = 'login_failed' 
             AND created_at >= DATE_SUB(NOW(), INTERVAL $timeWindow)"
        );
        
        $stmt->execute([$ipAddress]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['attempt_count'] ?? 0;
    }
    
    /**
     * Buscar último login bem-sucedido do usuário
     */
    public static function findLastSuccessfulLogin($db, $userId) {
        $stmt = $db->prepare(
            "SELECT * FROM security_logs 
             WHERE user_id = ? 
             AND activity_type = 'login_success' 
             ORDER BY created_at DESC 
             LIMIT 1"
        );
        
        $stmt->execute([$userId]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    
    /**
     * Estatísticas de segurança
     */
    public static function getSecurityStats($db, $days = 7) {
        $stmt = $db->prepare(
            "SELECT 
                activity_type,
                COUNT(*) as count,
                DATE(created_at) as date
             FROM security_logs 
             WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
             GROUP BY activity_type, DATE(created_at)
             ORDER BY date DESC, activity_type"
        );
        
        $stmt->execute([$days]);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Formatar estatísticas
        $stats = [];
        foreach ($results as $row) {
            $date = $row['date'];
            $type = $row['activity_type'];
            $count = $row['count'];
            
            if (!isset($stats[$date])) {
                $stats[$date] = [
                    'date' => $date,
                    'total' => 0,
                    'by_type' => []
                ];
            }
            
            $stats[$date]['by_type'][$type] = $count;
            $stats[$date]['total'] += $count;
        }
        
        return array_values($stats);
    }
    
    /**
     * Limpar logs antigos (manutenção)
     */
    public static function cleanupOldLogs($db, $daysToKeep = 90) {
        $stmt = $db->prepare(
            "DELETE FROM security_logs 
             WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)"
        );
        
        $stmt->execute([$daysToKeep]);
        return $stmt->rowCount();
    }
    
    /**
     * Buscar logs com paginação
     */
    public static function getPaginatedLogs($db, $page = 1, $perPage = 20, $filters = []) {
        $whereConditions = [];
        $params = [];
        
        // Aplicar filtros
        if (!empty($filters['user_id'])) {
            $whereConditions[] = "sl.user_id = ?";
            $params[] = $filters['user_id'];
        }
        
        if (!empty($filters['activity_type'])) {
            $whereConditions[] = "sl.activity_type = ?";
            $params[] = $filters['activity_type'];
        }
        
        if (!empty($filters['ip_address'])) {
            $whereConditions[] = "sl.ip_address LIKE ?";
            $params[] = $filters['ip_address'] . '%';
        }
        
        if (!empty($filters['start_date'])) {
            $whereConditions[] = "sl.created_at >= ?";
            $params[] = $filters['start_date'];
        }
        
        if (!empty($filters['end_date'])) {
            $whereConditions[] = "sl.created_at <= ?";
            $params[] = $filters['end_date'];
        }
        
        // Construir query WHERE
        $whereClause = '';
        if (!empty($whereConditions)) {
            $whereClause = 'WHERE ' . implode(' AND ', $whereConditions);
        }
        
        // Calcular offset
        $offset = ($page - 1) * $perPage;
        
        // Query para dados
        $sql = "
            SELECT sl.*, u.email, u.full_name 
            FROM security_logs sl
            LEFT JOIN users u ON sl.user_id = u.id
            $whereClause
            ORDER BY sl.created_at DESC 
            LIMIT ? OFFSET ?
        ";
        
        $params[] = $perPage;
        $params[] = $offset;
        
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Query para total
        $countSql = "
            SELECT COUNT(*) as total 
            FROM security_logs sl
            LEFT JOIN users u ON sl.user_id = u.id
            $whereClause
        ";
        
        $countStmt = $db->prepare($countSql);
        $countStmt->execute(array_slice($params, 0, -2)); // Remove LIMIT e OFFSET
        $total = $countStmt->fetch(PDO::FETCH_ASSOC)['total'];
        
        return [
            'logs' => $logs,
            'pagination' => [
                'page' => $page,
                'per_page' => $perPage,
                'total' => $total,
                'total_pages' => ceil($total / $perPage)
            ]
        ];
    }
    
    /**
     * Detectar padrões suspeitos
     */
    public static function detectSuspiciousPatterns($db) {
        $patterns = [];
        
        // Múltiplas tentativas de login falhas do mesmo IP
        $stmt = $db->prepare(
            "SELECT ip_address, COUNT(*) as attempts 
             FROM security_logs 
             WHERE activity_type = 'login_failed' 
             AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
             GROUP BY ip_address 
             HAVING attempts >= 5"
        );
        
        $stmt->execute();
        $patterns['failed_login_attempts'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Múltiplos usuários do mesmo IP em curto período
        $stmt = $db->prepare(
            "SELECT ip_address, COUNT(DISTINCT user_id) as unique_users 
             FROM security_logs 
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 MINUTE)
             AND user_id IS NOT NULL
             GROUP BY ip_address 
             HAVING unique_users >= 3"
        );
        
        $stmt->execute();
        $patterns['multiple_users_same_ip'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Atividades de usuário em múltiplas localizações
        $stmt = $db->prepare(
            "SELECT user_id, COUNT(DISTINCT ip_address) as locations 
             FROM security_logs 
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
             AND user_id IS NOT NULL
             GROUP BY user_id 
             HAVING locations >= 2"
        );
        
        $stmt->execute();
        $patterns['user_multiple_locations'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return $patterns;
    }
}

?>