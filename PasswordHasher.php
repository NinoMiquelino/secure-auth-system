<?php
// backend/utils/PasswordHasher.php

class PasswordHasher {
    private static $options = [
        'cost' => 12
    ];

    public static function hash($password) {
        return password_hash($password, PASSWORD_BCRYPT, self::$options);
    }

    public static function verify($password, $hash) {
        return password_verify($password, $hash);
    }

    public static function needsRehash($hash) {
        return password_needs_rehash($hash, PASSWORD_BCRYPT, self::$options);
    }
}

?>