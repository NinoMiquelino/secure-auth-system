<?php
// backend/index.php

require_once 'config/database.php';
require_once 'utils/JWTUtil.php';
require_once 'middleware/SecurityMiddleware.php';
require_once 'controllers/AuthController.php';

header("Content-Type: application/json");
header("Access-Control-Allow-Origin: http://localhost:3000");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

// Configurações
JWTUtil::init('seu_jwt_secret_super_seguro_aqui');

// Roteamento básico
$request = [
    'method' => $_SERVER['REQUEST_METHOD'],
    'path' => parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH),
    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    'headers' => [
        'authorization' => $_SERVER['HTTP_AUTHORIZATION'] ?? '',
        'user-agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
        'accept-language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''
    ]
];

try {
    $db = Database::getConnection();
    $security = new SecurityMiddleware($db);
    $authController = new AuthController($db);
    
    // Endpoints públicos (sem middleware de segurança)
    if ($request['path'] === '/api/login' && $request['method'] === 'POST') {
        $authController->login();
    } 
    elseif ($request['path'] === '/api/register' && $request['method'] === 'POST') {
        $authController->register();
    }
    elseif ($request['path'] === '/api/refresh-token' && $request['method'] === 'POST') {
        $authController->refreshToken();
    }
    // Endpoints protegidos (com middleware de segurança)
    elseif ($request['path'] === '/api/secure-action' && $request['method'] === 'POST') {
        // Aplica middleware de segurança completo
        $user = $security->handle($request);
        
        // Se chegou aqui, a requisição é válida - executar ação segura
        $authController->secureAction($user);
    }
    elseif ($request['path'] === '/api/logout' && $request['method'] === 'POST') {
        // Logout também precisa validar o token primeiro
        $user = $security->handle($request);
        $authController->logout($user);
    }
    elseif ($request['path'] === '/api/verify-token' && $request['method'] === 'GET') {
        // Verificação de token também protegida
        $user = $security->handle($request);
        $authController->verifyToken($user);
    }
    elseif ($request['path'] === '/api/security-logs' && $request['method'] === 'GET') {
        // Logs de segurança - requer autenticação
        $user = $security->handle($request);
        $authController->getSecurityLogs($user);
    }
    elseif ($request['path'] === '/api/security-stats' && $request['method'] === 'GET') {
        // Estatísticas - requer autenticação
        $user = $security->handle($request);
        $authController->getSecurityStats($user);
    }
    elseif ($request['method'] === 'OPTIONS') {
        // Preflight requests - responder OK
        http_response_code(200);
        exit();
    }
    else {
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint não encontrado']);
    }
    
} catch (Exception $e) {
    error_log("Application error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Erro interno do servidor']);
}
?>