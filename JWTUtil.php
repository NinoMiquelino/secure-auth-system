<?php
// backend/utils/JWTUtil.php

class JWTUtil {
    private static $secret;
    
    public static function init($secret) {
        self::$secret = $secret;
    }
    
    public static function generate($payload) {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $payload['jti'] = uniqid(); // JWT ID único
        $payload['iat'] = time(); // Issued at
        $payload['exp'] = time() + (60 * 60); // Expira em 1 hora
        
        $base64Header = self::base64UrlEncode($header);
        $base64Payload = self::base64UrlEncode(json_encode($payload));
        
        $signature = hash_hmac('sha256', 
            $base64Header . "." . $base64Payload, 
            self::$secret, 
            true
        );
        $base64Signature = self::base64UrlEncode($signature);
        
        return $base64Header . "." . $base64Payload . "." . $base64Signature;
    }
    
    public static function verify($token) {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new Exception('Invalid token format');
        }
        
        list($base64Header, $base64Payload, $base64Signature) = $parts;
        
        $signature = self::base64UrlDecode($base64Signature);
        $expectedSignature = hash_hmac('sha256', 
            $base64Header . "." . $base64Payload, 
            self::$secret, 
            true
        );
        
        if (!hash_equals($expectedSignature, $signature)) {
            throw new Exception('Invalid signature');
        }
        
        $payload = json_decode(self::base64UrlDecode($base64Payload));
        
        if ($payload->exp < time()) {
            throw new Exception('Token expired');
        }
        
        return $payload;
    }
    
    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    private static function base64UrlDecode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), 
            strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
?>