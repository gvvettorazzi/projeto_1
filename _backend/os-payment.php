<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

/*
 * Security-first payment state.
 *
 * IMPORTANT:
 * The browser is an untrusted environment.
 *
 * The payment amount MUST be stored server-side.
 * The cookie contains only an opaque, random identifier.
 *
 * Recommended server-side record:
 *
 *   payment_token_hash
 *   release_version
 *   amount
 *   user_id
 *   created_at
 *   expires_at
 *   revoked_at
 *
 * The database record must be protected by the application's authorization
 * layer and must never be exposed directly to the client.
 *
 * This design prevents:
 *
 * - client-side amount manipulation;
 * - disclosure of payment amounts through cookies;
 * - cookie replay after server-side revocation;
 * - release-name disclosure;
 * - subdomain cookie injection;
 * - plaintext payment information in browser storage.
 */

const OS_PAYMENT_MAX_VERSION_LENGTH = 128;
const OS_PAYMENT_TOKEN_BYTES = 32;
const OS_PAYMENT_COOKIE_LIFETIME = 31536000;
const OS_PAYMENT_COOKIE_PREFIX = '__Host-os_payment_';

/**
 * Validates a release version.
 *
 * Only application-generated release identifiers should reach this function.
 *
 * @param string $version
 * @return string|null
 */
function os_payment_normalize_version(string $version): ?string
{
    $version = trim($version);

    if (
        $version === ''
        || strlen($version) > OS_PAYMENT_MAX_VERSION_LENGTH
        || preg_match(
            '/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/D',
            $version
        ) !== 1
    ) {
        return null;
    }

    return $version;
}

/**
 * Generates an opaque cookie name.
 *
 * The actual release version is not disclosed to the browser.
 *
 * @param string $version
 * @return string|null
 */
function os_payment_cookie_name(string $version): ?string
{
    $version = os_payment_normalize_version($version);

    if ($version === null) {
        return null;
    }

    /*
     * SHA-256 is used only as a public identifier derivation function.
     * It is NOT being used for password storage or authentication.
     */
    $digest = hash('sha256', $version, true);

    return OS_PAYMENT_COOKIE_PREFIX
        . rtrim(
            strtr(
                base64_encode($digest),
                '+/',
                '-_'
            ),
            '='
        );
}

/**
 * Generates an opaque payment reference.
 *
 * The returned value contains no payment amount, user ID or other
 * application information.
 *
 * @return string|null
 */
function os_payment_generate_token(): ?string
{
    try {
        $token = random_bytes(OS_PAYMENT_TOKEN_BYTES);
    } catch (Throwable) {
        return null;
    }

    return rtrim(
        strtr(
            base64_encode($token),
            '+/',
            '-_'
        ),
        '='
    );
}

/**
 * Hashes a payment token before it is persisted server-side.
 *
 * The raw token should NEVER be stored in the database.
 *
 * @param string $token
 * @return string
 */
function os_payment_hash_token(string $token): string
{
    return hash('sha256', $token);
}

/**
 * Constant-time comparison of token hashes.
 *
 * @param string $storedHash
 * @param string $providedHash
 * @return bool
 */
function os_payment_token_matches(
    string $storedHash,
    string $providedHash
): bool {
    if (
        $storedHash === ''
        || $providedHash === ''
        || strlen($storedHash) !== 64
        || strlen($providedHash) !== 64
    ) {
        return false;
    }

    return hash_equals(
        $storedHash,
        $providedHash
    );
}

/**
 * Returns the payment cookie lifetime.
 *
 * @return int
 */
function os_payment_cookie_lifetime(): int
{
    return OS_PAYMENT_COOKIE_LIFETIME;
}

/**
 * Creates the payment cookie.
 *
 * IMPORTANT:
 * The amount is deliberately NOT stored in the cookie.
 *
 * The caller must first create a server-side payment record and then pass
 * the opaque token returned by that operation.
 *
 * @param string $version
 * @param string $token
 * @return bool
 */
function os_payment_setcookie(
    string $version,
    string $token
): bool {
    $cookieName = os_payment_cookie_name($version);

    if (
        $cookieName === null
        || $token === ''
        || strlen($token) > 512
        || !os_payment_is_https()
    ) {
        return false;
    }

    /*
     * __Host- cookie requirements:
     *
     * Secure=true
     * Path=/
     * no Domain attribute
     *
     * This prevents weaker cookie scoping and reduces subdomain
     * cookie-injection risks.
     */
    return setcookie(
        $cookieName,
        $token,
        [
            'expires' => time()
                + OS_PAYMENT_COOKIE_LIFETIME,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]
    );
}

/**
 * Retrieves the opaque payment token.
 *
 * No payment amount is read from the client.
 *
 * @param string $version
 * @return string|null
 */
function os_payment_getcookie(
    string $version
): ?string {
    $cookieName = os_payment_cookie_name($version);

    if (
        $cookieName === null
        || !isset($_COOKIE[$cookieName])
        || !is_string($_COOKIE[$cookieName])
    ) {
        return null;
    }

    $token = $_COOKIE[$cookieName];

    /*
     * The token is expected to be Base64URL.
     *
     * This prevents arbitrary data from being passed into downstream
     * database/application operations.
     */
    if (
        $token === ''
        || strlen($token) > 512
        || preg_match(
            '/\A[A-Za-z0-9_-]+\z/D',
            $token
        ) !== 1
    ) {
        return null;
    }

    return $token;
}

/**
 * Removes the payment cookie.
 *
 * @param string $version
 * @return bool
 */
function os_payment_clearcookie(
    string $version
): bool {
    $cookieName = os_payment_cookie_name($version);

    if (
        $cookieName === null
        || !os_payment_is_https()
    ) {
        return false;
    }

    return setcookie(
        $cookieName,
        '',
        [
            'expires' => 1,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]
    );
}

/**
 * HTTPS detection.
 *
 * Do not trust arbitrary client-controlled forwarding headers.
 *
 * @return bool
 */
function os_payment_is_https(): bool
{
    return isset($_SERVER['HTTPS'])
        && strtolower(
            (string) $_SERVER['HTTPS']
        ) === 'on';
}

/**
 * Securely hashes a password.
 *
 * Argon2id is preferred.
 * Bcrypt is retained only for environments where Argon2id is unavailable.
 *
 * @param string $password
 * @return string|null
 */
function os_payment_password_hash(
    string $password
): ?string {
    /*
     * Do not silently truncate passwords.
     *
     * A maximum size protects the application from pathological requests
     * while still allowing long passphrases.
     */
    if (
        $password === ''
        || strlen($password) > 1024
    ) {
        return null;
    }

    try {
        if (defined('PASSWORD_ARGON2ID')) {
            $hash = password_hash(
                $password,
                PASSWORD_ARGON2ID,
                [
                    'memory_cost' => 19456,
                    'time_cost' => 2,
                    'threads' => 1,
                ]
            );
        } else {
            $hash = password_hash(
                $password,
                PASSWORD_BCRYPT,
                [
                    'cost' => 12,
                ]
            );
        }
    } catch (Throwable) {
        return null;
    }

    return is_string($hash)
        ? $hash
        : null;
}

/**
 * Verifies a password.
 *
 * @param string $password
 * @param string $hash
 * @return bool
 */
function os_payment_password_verify(
    string $password,
    string $hash
): bool {
    if (
        $password === ''
        || strlen($password) > 1024
        || $hash === ''
        || strlen($hash) > 1024
    ) {
        return false;
    }

    return password_verify(
        $password,
        $hash
    );
}

/**
 * Determines whether a password hash should be upgraded.
 *
 * @param string $hash
 * @return bool
 */
function os_payment_password_needs_rehash(
    string $hash
): bool {
    if (
        $hash === ''
        || strlen($hash) > 1024
    ) {
        return false;
    }

    if (defined('PASSWORD_ARGON2ID')) {
        return password_needs_rehash(
            $hash,
            PASSWORD_ARGON2ID,
            [
                'memory_cost' => 19456,
                'time_cost' => 2,
                'threads' => 1,
            ]
        );
    }

    return password_needs_rehash(
        $hash,
        PASSWORD_BCRYPT,
        [
            'cost' => 12,
        ]
    );
}

/**
 * Configures secure PHP sessions.
 *
 * Call BEFORE session_start().
 *
 * @return bool
 */
function os_payment_configure_session(): bool
{
    if (!os_payment_is_https()) {
        return false;
    }

    ini_set(
        'session.use_only_cookies',
        '1'
    );

    ini_set(
        'session.use_strict_mode',
        '1'
    );

    ini_set(
        'session.use_trans_sid',
        '0'
    );

    ini_set(
        'session.cookie_secure',
        '1'
    );

    ini_set(
        'session.cookie_httponly',
        '1'
    );

    if (PHP_VERSION_ID >= 70300) {
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    return true;
}

/**
 * Regenerates the session identifier after authentication.
 *
 * @return bool
 */
function os_payment_regenerate_session(): bool
{
    if (
        session_status()
        !== PHP_SESSION_ACTIVE
    ) {
        return false;
    }

    return session_regenerate_id(true);
}

/**
 * Creates a CSRF token associated with the server-side session.
 *
 * @return string|null
 */
function os_payment_csrf_token(): ?string
{
    if (
        session_status()
        !== PHP_SESSION_ACTIVE
    ) {
        return null;
    }

    if (
        isset($_SESSION['csrf_token'])
        && is_string($_SESSION['csrf_token'])
        && strlen($_SESSION['csrf_token']) >= 32
    ) {
        return $_SESSION['csrf_token'];
    }

    try {
        $token = bin2hex(
            random_bytes(32)
        );
    } catch (Throwable) {
        return null;
    }

    $_SESSION['csrf_token'] = $token;

    return $token;
}

/**
 * Validates a CSRF token.
 *
 * @param mixed $provided
 * @return bool
 */
function os_payment_verify_csrf(
    mixed $provided
): bool {
    if (
        session_status()
        !== PHP_SESSION_ACTIVE
        || !isset($_SESSION['csrf_token'])
        || !is_string($_SESSION['csrf_token'])
        || !is_string($provided)
    ) {
        return false;
    }

    if (
        strlen($provided) !== 64
        || preg_match(
            '/\A[0-9a-f]{64}\z/D',
            $provided
        ) !== 1
    ) {
        return false;
    }

    return hash_equals(
        $_SESSION['csrf_token'],
        $provided
    );
}

/**
 * Generates a server-side rate-limit identifier.
 *
 * The raw identifier should not be persisted or logged.
 *
 * @param string $identifier
 * @return string
 */
function os_payment_rate_limit_key(
    string $identifier
): string {
    /*
     * The identifier is deliberately hashed before being used by a
     * distributed rate-limiting system.
     *
     * A production implementation should use Redis or another atomic,
     * shared store.
     */
    return hash(
        'sha256',
        $identifier
    );
}

/**
 * Returns a generic authentication failure.
 *
 * The caller must not reveal whether the username/account exists.
 *
 * @return bool
 */
function os_payment_authentication_failure(): bool
{
    return false;
}

/**
 * Sends restrictive security headers.
 *
 * Must be called before output.
 */
function os_payment_send_security_headers(): void
{
    if (headers_sent()) {
        return;
    }

    header(
        'Cache-Control: no-store'
    );

    header(
        'Pragma: no-cache'
    );

    header(
        'X-Content-Type-Options: nosniff'
    );

    header(
        'X-Frame-Options: DENY'
    );

    header(
        'Referrer-Policy: no-referrer'
    );

    header(
        'Permissions-Policy: ' .
        'camera=(), ' .
        'microphone=(), ' .
        'geolocation=(), ' .
        'payment=()'
    );

    header(
        'Content-Security-Policy: ' .
        "default-src 'self'; " .
        "base-uri 'self'; " .
        "object-src 'none'; " .
        "frame-ancestors 'none'; " .
        "form-action 'self'; " .
        "script-src 'self'; " .
        "style-src 'self'; " .
        "img-src 'self' data:; " .
        "font-src 'self'; " .
        "connect-src 'self'"
    );

    if (os_payment_is_https()) {
        header(
            'Strict-Transport-Security: ' .
            'max-age=31536000; includeSubDomains'
        );
    }
}

/**
 * Redacts sensitive values from logs/errors.
 *
 * Never log the actual value.
 *
 * @param mixed $value
 * @return string
 */
function os_payment_redact(
    mixed $value
): string {
    return '[REDACTED]';
}

/**
 * Explicitly disables the old plaintext-cookie mechanism.
 *
 * The old implementation allowed the client to supply the payment amount.
 * That trust model is intentionally removed.
 *
 * @return int
 */
function os_payment_get_legacy_cookie(): int
{
    return 0;
}
