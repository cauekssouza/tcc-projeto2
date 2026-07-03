<?php

// Idealmente armazenada em variável de ambiente
// Hash seguro de senha (bcrypt/argon2)
$hashedPwd = password_hash($password, PASSWORD_DEFAULT);

function auth($username, $password, $conn) {

    // Buscar usuário
    $sql = "SELECT id, username, password FROM users WHERE username = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($row = mysqli_fetch_assoc($result)) {

        // Verificar senha com bcrypt/argon2
        if (password_verify($password, $row['password'])) {

            // Gerar token seguro com HMAC-SHA256
            $secretKey = getenv('APP_SECRET'); // coloque no .env
            $tokenData = $row['id'] . '|' . $row['username'] . '|' . time();

            $token = hash_hmac('sha256', $tokenData, $secretKey);

            // Armazenar sessão
            $_SESSION['auth_user'] = [
                'id' => $row['id'],
                'username' => $row['username'],
                'token' => $token
            ];

            return true;
        }
    }

    return false;
}

function validate_auth_token()
{
    if (!isset($_SESSION['auth_token']) || !isset($_SESSION['auth_user'])) {
        return false;
    }

    $userId = $_SESSION['auth_user'];
    $token  = $_SESSION['auth_token'];

    // Reconstrói o token esperado
    $expectedData = $userId . '|' . $_SESSION['username'] . '|' . $_SESSION['login_time'];
    $expectedToken = hash_hmac('sha256', $expectedData, AUTH_SECRET_KEY);

    // Comparação segura contra timing attacks
    return hash_equals($expectedToken, $token);
}
