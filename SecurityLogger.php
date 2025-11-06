<?php
// backend/utils/SecurityLogger.php

class SecurityLogger {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    public function logActivity($userId, $ipAddress, $userAgent, $activityType, $description = '') {
        $stmt = $this->db->prepare(
            "INSERT INTO security_logs (user_id, ip_address, user_agent, activity_type, description) 
             VALUES (?, ?, ?, ?, ?)"
        );
        
        $stmt->execute([
            $userId,
            $ipAddress,
            $userAgent,
            $activityType,
            $description
        ]);

        // Também logar em arquivo para backup
        $logMessage = sprintf(
            "[%s] UserID: %s | IP: %s | Activity: %s | Description: %s\n",
            date('Y-m-d H:i:s'),
            $userId ?? 'anonymous',
            $ipAddress,
            $activityType,
            $description
        );

        error_log($logMessage, 3, __DIR__ . '/../logs/security.log');
    }

    public function getRecentActivities($userId = null, $limit = 50) {
        $sql = "SELECT * FROM security_logs";
        $params = [];

        if ($userId) {
            $sql .= " WHERE user_id = ?";
            $params[] = $userId;
        }

        $sql .= " ORDER BY created_at DESC LIMIT ?";
        $params[] = $limit;

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

?>