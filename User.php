<?php
// backend/models/User.php

require_once __DIR__ . '/../utils/PasswordHasher.php';

class User {
    public static function findByEmail($db, $email) {
        $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public static function findById($db, $id) {
        $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public static function create($db, $data) {
        $stmt = $db->prepare(
            "INSERT INTO users (email, password_hash, full_name) VALUES (?, ?, ?)"
        );
        
        $passwordHash = PasswordHasher::hash($data['password']);
        
        $stmt->execute([
            $data['email'],
            $passwordHash,
            $data['full_name']
        ]);

        return $db->lastInsertId();
    }

    public static function update($db, $id, $data) {
        $allowedFields = ['email', 'full_name', 'is_active'];
        $updates = [];
        $params = [];

        foreach ($data as $field => $value) {
            if (in_array($field, $allowedFields)) {
                $updates[] = "{$field} = ?";
                $params[] = $value;
            }
        }

        if (empty($updates)) {
            return false;
        }

        $params[] = $id;
        $sql = "UPDATE users SET " . implode(', ', $updates) . ", updated_at = NOW() WHERE id = ?";
        
        $stmt = $db->prepare($sql);
        return $stmt->execute($params);
    }
}

?>