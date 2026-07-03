<?php

/**
 * Auth function rewritten to remove MD5 and use HMAC-SHA256,
 * following OWASP recommendations.
 */

function auth($username, $password, $conn)
{
    // Load secret key from environment or secure config file
    $secretKey = getenv('AUTH_SECRET_KEY');

    if (!$secretKey) {
        throw new Exception("Missing AUTH_SECRET_KEY");
    }

    // Clean input
    $username = trim($username);
    $password = trim($password);

    // Fetch user from DB
    $sql = "SELECT id, username, password FROM users WHERE username = ?";
    $stmt = mysqli_stmt_init($conn);

    if (!mysqli_stmt_prepare($stmt, $sql)) {
        return false;
    }

    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($row = mysqli_fetch_assoc($result)) {

        // Verify password using password_hash()
        if (password_verify($password, $row['password'])) {

            /**
             * Generate secure authentication token
             * Replaces old insecure MD5 token
             */
            $tokenPayload = $row['id'] . '|' . $row['username'] . '|' . time();

            // HMAC-SHA256 token
            $token = hash_hmac('sha256', $tokenPayload, $secretKey);

            // Store token in session
            $_SESSION['auth_token'] = $token;
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['username'] = $row['username'];

            return true;
        }
    }

    return false;
}
