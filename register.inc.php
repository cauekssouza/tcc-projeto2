<?php

/**
 * Auth token generator and validator using HMAC-SHA256
 * OWASP-compliant replacement for insecure MD5-based logic
 */

function auth_generate_token(string $userId): string
{
    // Load secret key from environment or secure config file
    $secretKey = getenv('AUTH_SECRET_KEY');

    if (!$secretKey) {
        throw new Exception("Missing AUTH_SECRET_KEY");
    }

    // Token payload (can include timestamp, user agent, etc.)
    $payload = json_encode([
        'uid' => $userId,
        'ts'  => time()
    ]);

    // Generate HMAC-SHA256 signature
    $signature = hash_hmac('sha256', $payload, $secretKey);

    // Final token (payload + signature)
    return base64_encode($payload . '.' . $signature);
}


function auth_validate_token(string $token): bool
{
    $secretKey = getenv('AUTH_SECRET_KEY');

    if (!$secretKey) {
        return false;
    }

    // Decode token
    $decoded = base64_decode($token, true);
    if (!$decoded || !str_contains($decoded, '.')) {
        return false;
    }

    list($payload, $providedSignature) = explode('.', $decoded, 2);

    // Recalculate expected signature
    $expectedSignature = hash_hmac('sha256', $payload, $secretKey);

    // Constant‑time comparison (prevents timing attacks)
    if (!hash_equals($expectedSignature, $providedSignature)) {
        return false;
    }

    // Validate payload
    $data = json_decode($payload, true);
    if (!$data || !isset($data['uid'], $data['ts'])) {
        return false;
    }

    // Optional: token expiration (e.g., 30 minutes)
    if (time() - $data['ts'] > 1800) {
        return false;
    }

    return true;
}
