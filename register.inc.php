<?php

// Idealmente armazenada em variável de ambiente
define('AUTH_SECRET_KEY', getenv('AUTH_SECRET_KEY') ?: 'CHAVE_SUPER_SECRETA_ALTERE_ISTO');

function auth($username, $password, $conn)
{
    // Sanitização mínima (idealmente já feita antes)
    $username = trim($username);

    // Buscar usuário no banco
    $sql = "SELECT id, username, password FROM users WHERE username = ?";
    $stmt = mysqli_stmt_init($conn);

    if (!mysqli_stmt_prepare($stmt, $sql)) {
        return false;
    }

    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($row = mysqli_fetch_assoc($result)) {

        // Verifica senha usando password_verify (OWASP recomendado)
        if (!password_verify($password, $row['password'])) {
            return false;
        }

        /*
        |--------------------------------------------------------------------------
        | Token seguro baseado em HMAC-SHA256
        |--------------------------------------------------------------------------
        |
        | Substitui qualquer uso antigo de md5($username . $password)
        | por um token moderno e resistente a colisões.
        |
        */

        $tokenData = $row['id'] . '|' . $row['username'] . '|' . time();

        // Gera token seguro
        $token = hash_hmac('sha256', $tokenData, AUTH_SECRET_KEY);

        // Armazena token na sessão
        $_SESSION['auth_token'] = $token;
        $_SESSION['auth_user']  = $row['id'];

        return true;
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
