<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

/**
 * High-security payment state management.
 *
 * IMPORTANT:
 * This file deliberately does NOT trust payment information supplied by the
 * client. A browser cookie is only an encrypted/authenticated representation
 * of state and must never be treated as an authentication credential.
 *
 * For maximum confidentiality:
 * - never log cookie values, passwords, tokens or encryption keys;
 * - keep the encryption key exclusively on the server;
 * - use HTTPS exclusively;
 * - enforce authorization independently from payment state;
 * - prefer server-side payment records for authoritative financial state;
 * - use a database transaction/idempotency mechanism when recording payments;
 * - rate-limit the authentication/payment endpoints at the application and
 *   infrastructure layers.
 *
 * OWASP recommends Argon2id for password storage and secure session/token
 * handling. PHP's password_hash()/password_verify() should be used for
 * passwords rather than reversible encryption.
 */

/* ------------------------------------------------------------------------- */
/* Configuration                                                             */
/* ------------------------------------------------------------------------- */

const OS_PAYMENT_MAX_VERSION_LENGTH = 128;
const OS_PAYMENT_MAX_COOKIE_VALUE_LENGTH = 4096;
const OS_PAYMENT_COOKIE_LIFETIME = 31536000;

/*
 * Versioned opaque cookie name.
 *
 * __Host- requires:
 *   - Secure
 *   - Path=/
 *   - no Domain attribute
 *
 * This substantially reduces the possibility of cookie injection from
 * subdomains.
 */
const OS_PAYMENT_COOKIE_PREFIX = '__Host-os_payment_';

const OS_PAYMENT_CRYPTO_VERSION = 1;

/*
 * Conservative password limits.
 *
 * The limit is intentionally finite to prevent resource-exhaustion attacks,
 * while still allowing long passphrases.
 */
const OS_PAYMENT_PASSWORD_MIN_LENGTH = 15;
const OS_PAYMENT_PASSWORD_MAX_BYTES = 1024;

/*
 * Argon2id parameters.
 *
 * These should be benchmarked on the production infrastructure and increased
 * where operationally possible. The minimum baseline follows OWASP guidance.
 */
const OS_PAYMENT_ARGON2_MEMORY_COST = 19456;
const OS_PAYMENT_ARGON2_TIME_COST = 2;
const OS_PAYMENT_ARGON2_THREADS = 1;

const OS_PAYMENT_BCRYPT_COST = 12;

/*
 * Generic authentication limits.
 *
 * This function does not implement a distributed rate limiter by itself.
 * Production authentication endpoints should additionally use Redis,
 * a database-backed counter, WAF/API-gateway controls, or equivalent.
 */
const OS_PAYMENT_MAX_AUTH_ATTEMPTS_PER_WINDOW = 5;
const OS_PAYMENT_AUTH_WINDOW_SECONDS = 900;

/* ------------------------------------------------------------------------- */
/* Generic secure helpers                                                    */
/* ------------------------------------------------------------------------- */

/**
 * Securely compares two secrets.
 *
 * hash_equals() is used instead of == or === for secret material.
 *
 * @param string $known
 * @param string $provided
 * @return bool
 */
function os_payment_secure_equals(
    string $known,
    string $provided
): bool {
    return hash_equals($known, $provided);
}

/**
 * Generates cryptographically secure random bytes.
 *
 * @param int $length
 * @return string|null
 */
function os_payment_random_bytes(int $length): ?string
{
    if ($length < 1 || $length > 4096) {
        return null;
    }

    try {
        return random_bytes($length);
    } catch (Throwable) {
        return null;
    }
}

/**
 * Encodes binary data using unpadded Base64URL.
 *
 * @param string $data
 * @return string
 */
function os_payment_base64url_encode(string $data): string
{
    return rtrim(
        strtr(base64_encode($data), '+/', '-_'),
        '='
    );
}

/**
 * Strictly decodes unpadded Base64URL.
 *
 * @param mixed $value
 * @return string|null
 */
function os_payment_base64url_decode(mixed $value): ?string
{
    if (!is_string($value)) {
        return null;
    }

    if (
        $value === ''
        || strlen($value) > OS_PAYMENT_MAX_COOKIE_VALUE_LENGTH
        || preg_match('/\A[A-Za-z0-9_-]+\z/D', $value) !== 1
    ) {
        return null;
    }

    $padding = strlen($value) % 4;

    if ($padding !== 0) {
        $value .= str_repeat('=', 4 - $padding);
    }

    $decoded = base64_decode(
        strtr($value, '-_', '+/'),
        true
    );

    return $decoded === false ? null : $decoded;
}

/**
 * Determines whether the current connection is HTTPS.
 *
 * No X-Forwarded-Proto or other attacker-controlled proxy header is trusted.
 *
 * @return bool
 */
function os_payment_is_https(): bool
{
    return isset($_SERVER['HTTPS'])
        && strtolower((string) $_SERVER['HTTPS']) === 'on';
}

/**
 * Returns a generic non-sensitive error value.
 *
 * Do not expose internal cryptographic/configuration failures to clients.
 *
 * @return null
 */
function os_payment_fail_closed(): mixed
{
    return null;
}

/* ------------------------------------------------------------------------- */
/* Release validation                                                        */
/* ------------------------------------------------------------------------- */

/**
 * Validates a release version.
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
 * Creates an opaque cookie name.
 *
 * The release version is hashed so the cookie name does not expose the
 * application's release identifier.
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

    $digest = hash(
        'sha256',
        $version,
        true
    );

    return OS_PAYMENT_COOKIE_PREFIX
        . os_payment_base64url_encode($digest);
}

/* ------------------------------------------------------------------------- */
/* Cryptographic key management                                              */
/* ------------------------------------------------------------------------- */

/**
 * Loads the payment-cookie encryption key.
 *
 * The preferred production source is a dedicated secret manager exposed to
 * the application as an environment secret.
 *
 * Accepted formats:
 *   - 64 hexadecimal characters
 *   - base64 containing exactly 32 bytes
 *   - raw 32-byte binary value
 *
 * @return string|null
 */
function os_payment_get_key(): ?string
{
    global $config;

    $configured = null;

    if (
        is_array($config ?? null)
        && isset($config['payment_cookie_key'])
        && is_string($config['payment_cookie_key'])
    ) {
        $configured = $config['payment_cookie_key'];
    }

    if ($configured === null || $configured === '') {
        $environment = getenv('PAYMENT_COOKIE_KEY');

        if (
            is_string($environment)
            && $environment !== ''
        ) {
            $configured = $environment;
        }
    }

    if (!is_string($configured) || $configured === '') {
        return null;
    }

    /*
     * Preferred configuration format: hexadecimal.
     */
    if (
        strlen($configured) === 64
        && ctype_xdigit($configured)
    ) {
        $decoded = hex2bin($configured);

        if (
            $decoded !== false
            && strlen($decoded) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES
        ) {
            return $decoded;
        }
    }

    /*
     * Base64 is accepted for operational compatibility.
     */
    $decoded = base64_decode($configured, true);

    if (
        $decoded !== false
        && strlen($decoded) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES
    ) {
        return $decoded;
    }

    /*
     * Raw binary key.
     */
    if (
        strlen($configured)
        === SODIUM_CRYPTO_SECRETBOX_KEYBYTES
    ) {
        return $configured;
    }

    return null;
}

/**
 * Generates a new encryption key.
 *
 * This function is useful during deployment/secret provisioning.
 *
 * @return string|null
 */
function os_payment_generate_key(): ?string
{
    $key = os_payment_random_bytes(
        SODIUM_CRYPTO_SECRETBOX_KEYBYTES
    );

    if ($key === null) {
        return null;
    }

    return bin2hex($key);
}

/* ------------------------------------------------------------------------- */
/* Payment amount validation                                                 */
/* ------------------------------------------------------------------------- */

/**
 * Parses an amount received from an untrusted source.
 *
 * @param mixed $value
 * @return int|null
 */
function os_payment_parse_amount(mixed $value): ?int
{
    if (!is_string($value)) {
        return null;
    }

    /*
     * Do not accept whitespace, signs, decimals, scientific notation,
     * hexadecimal values or partially numeric strings.
     */
    if (
        $value === ''
        || strlen($value) > 19
        || preg_match(
            '/\A(?:0|[1-9][0-9]*)\z/D',
            $value
        ) !== 1
    ) {
        return null;
    }

    $maximum = (string) PHP_INT_MAX;

    if (
        strlen($value) > strlen($maximum)
        || (
            strlen($value) === strlen($maximum)
            && strcmp($value, $maximum) > 0
        )
    ) {
        return null;
    }

    $amount = filter_var(
        $value,
        FILTER_VALIDATE_INT,
        [
            'options' => [
                'min_range' => 0,
            ],
        ]
    );

    return $amount === false ? null : $amount;
}

/* ------------------------------------------------------------------------- */
/* Authenticated encryption                                                  */
/* ------------------------------------------------------------------------- */

/**
 * Encrypts payment state.
 *
 * Secretbox provides confidentiality + authentication.
 *
 * @param int $amount
 * @return string|null
 */
function os_payment_encrypt_amount(int $amount): ?string
{
    if ($amount < 0) {
        return null;
    }

    $key = os_payment_get_key();

    if ($key === null) {
        return null;
    }

    $nonce = os_payment_random_bytes(
        SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
    );

    if ($nonce === null) {
        return null;
    }

    try {
        $plaintext = json_encode(
            [
                'v' => OS_PAYMENT_CRYPTO_VERSION,
                'amount' => (string) $amount,
            ],
            JSON_THROW_ON_ERROR
            | JSON_UNESCAPED_SLASHES
        );

        $ciphertext = sodium_crypto_secretbox(
            $plaintext,
            $nonce,
            $key
        );
    } catch (Throwable) {
        return null;
    }

    return os_payment_base64url_encode(
        chr(OS_PAYMENT_CRYPTO_VERSION)
        . $nonce
        . $ciphertext
    );
}

/**
 * Decrypts and authenticates payment state.
 *
 * @param mixed $value
 * @return int|null
 */
function os_payment_decrypt_amount(mixed $value): ?int
{
    if (!is_string($value)) {
        return null;
    }

    $encoded = os_payment_base64url_decode($value);

    if ($encoded === null) {
        return null;
    }

    $minimumLength =
        1
        + SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
        + SODIUM_CRYPTO_SECRETBOX_MACBYTES;

    if (strlen($encoded) < $minimumLength) {
        return null;
    }

    $version = ord($encoded[0]);

    if ($version !== OS_PAYMENT_CRYPTO_VERSION) {
        return null;
    }

    $nonce = substr(
        $encoded,
        1,
        SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
    );

    $ciphertext = substr(
        $encoded,
        1 + SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
    );

    if (
        $nonce === false
        || $ciphertext === false
        || $ciphertext === ''
    ) {
        return null;
    }

    $key = os_payment_get_key();

    if ($key === null) {
        return null;
    }

    try {
        /*
         * Authentication is verified before plaintext is returned.
         */
        $plaintext = sodium_crypto_secretbox_open(
            $ciphertext,
            $nonce,
            $key
        );
    } catch (Throwable) {
        return null;
    }

    if ($plaintext === false) {
        return null;
    }

    try {
        $payload = json_decode(
            $plaintext,
            true,
            8,
            JSON_THROW_ON_ERROR
        );
    } catch (Throwable) {
        return null;
    }

    if (
        !is_array($payload)
        || ($payload['v'] ?? null)
            !== OS_PAYMENT_CRYPTO_VERSION
        || !isset($payload['amount'])
        || !is_string($payload['amount'])
    ) {
        return null;
    }

    return os_payment_parse_amount(
        $payload['amount']
    );
}

/* ------------------------------------------------------------------------- */
/* Payment cookies                                                           */
/* ------------------------------------------------------------------------- */

/**
 * Creates the secure payment cookie.
 *
 * Payment cookies cannot be issued over HTTP.
 *
 * @param string $version
 * @param int $amount
 * @return bool
 */
function os_payment_setcookie(
    string $version,
    int $amount
): bool {
    $version = os_payment_normalize_version($version);

    if (
        $version === null
        || $amount < 0
        || !os_payment_is_https()
    ) {
        return false;
    }

    $cookieName = os_payment_cookie_name($version);

    if ($cookieName === null) {
        return false;
    }

    $cookieValue = os_payment_encrypt_amount($amount);

    if (
        $cookieValue === null
        || strlen($cookieValue)
            > OS_PAYMENT_MAX_COOKIE_VALUE_LENGTH
    ) {
        return false;
    }

    /*
     * No Domain attribute is deliberately specified.
     *
     * SameSite=Strict is selected because payment state does not normally
     * need to be sent during cross-site navigation.
     */
    return setcookie(
        $cookieName,
        $cookieValue,
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
 * Reads authenticated payment state.
 *
 * Legacy plaintext payment cookies are intentionally NOT accepted.
 *
 * @param string $version
 * @return int
 */
function os_payment_getcookie(string $version): int
{
    $version = os_payment_normalize_version($version);

    if ($version === null) {
        return 0;
    }

    $cookieName = os_payment_cookie_name($version);

    if (
        $cookieName === null
        || !array_key_exists($cookieName, $_COOKIE)
    ) {
        return 0;
    }

    $amount = os_payment_decrypt_amount(
        $_COOKIE[$cookieName]
    );

    /*
     * Fail closed:
     * malformed, forged, modified or obsolete cookies mean "not paid".
     */
    return $amount ?? 0;
}

/**
 * Deletes the payment cookie.
 *
 * @param string $version
 * @return bool
 */
function os_payment_clearcookie(string $version): bool
{
    $version = os_payment_normalize_version($version);

    if (
        $version === null
        || !os_payment_is_https()
    ) {
        return false;
    }

    $cookieName = os_payment_cookie_name($version);

    if ($cookieName === null) {
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

/* ------------------------------------------------------------------------- */
/* Password security                                                         */
/* ------------------------------------------------------------------------- */

/**
 * Validates password size without silently truncating it.
 *
 * @param string $password
 * @return bool
 */
function os_payment_password_is_valid(
    string $password
): bool {
    if ($password === '') {
        return false;
    }

    $length = strlen($password);

    return $length >= OS_PAYMENT_PASSWORD_MIN_LENGTH
        && $length <= OS_PAYMENT_PASSWORD_MAX_BYTES;
}

/**
 * Creates an Argon2id password hash.
 *
 * Bcrypt is used only as a compatibility fallback when Argon2id is not
 * available in the installed PHP build.
 *
 * @param string $password
 * @return string|null
 */
function os_payment_password_hash(
    string $password
): ?string {
    if (!os_payment_password_is_valid($password)) {
        return null;
    }

    try {
        if (defined('PASSWORD_ARGON2ID')) {
            $hash = password_hash(
                $password,
                PASSWORD_ARGON2ID,
                [
                    'memory_cost'
                        => OS_PAYMENT_ARGON2_MEMORY_COST,
                    'time_cost'
                        => OS_PAYMENT_ARGON2_TIME_COST,
                    'threads'
                        => OS_PAYMENT_ARGON2_THREADS,
                ]
            );
        } else {
            $hash = password_hash(
                $password,
                PASSWORD_BCRYPT,
                [
                    'cost' => OS_PAYMENT_BCRYPT_COST,
                ]
            );
        }
    } catch (Throwable) {
        return null;
    }

    return is_string($hash) ? $hash : null;
}

/**
 * Verifies a password securely.
 *
 * password_verify() performs the appropriate secure verification against
 * modern PHP password hashes.
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
        !os_payment_password_is_valid($password)
        || $hash === ''
        || strlen($hash) > 1024
    ) {
        return false;
    }

    try {
        return password_verify(
            $password,
            $hash
        );
    } catch (Throwable) {
        return false;
    }
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
    if ($hash === '' || strlen($hash) > 1024) {
        return false;
    }

    try {
        if (defined('PASSWORD_ARGON2ID')) {
            return password_needs_rehash(
                $hash,
                PASSWORD_ARGON2ID,
                [
                    'memory_cost'
                        => OS_PAYMENT_ARGON2_MEMORY_COST,
                    'time_cost'
                        => OS_PAYMENT_ARGON2_TIME_COST,
                    'threads'
                        => OS_PAYMENT_ARGON2_THREADS,
                ]
            );
        }

        return password_needs_rehash(
            $hash,
            PASSWORD_BCRYPT,
            [
                'cost' => OS_PAYMENT_BCRYPT_COST,
            ]
        );
    } catch (Throwable) {
        return false;
    }
}

/* ------------------------------------------------------------------------- */
/* Secure authentication/session primitives                                  */
/* ------------------------------------------------------------------------- */

/**
 * Generates an opaque authentication/session token.
 *
 * Only the token should be sent to the client. Associated identity,
 * privileges and expiration state belong server-side.
 *
 * @return string|null
 */
function os_payment_generate_auth_token(): ?string
{
    $random = os_payment_random_bytes(32);

    if ($random === null) {
        return null;
    }

    return os_payment_base64url_encode($random);
}

/**
 * Starts a hardened PHP session.
 *
 * This function should be called before session_start().
 *
 * @return bool
 */
function os_payment_configure_session(): bool
{
    if (!os_payment_is_https()) {
        return false;
    }

    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_trans_sid', '0');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_secure', '1');

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
 * Regenerates the session identifier after authentication or privilege
 * changes, mitigating session fixation.
 *
 * @return bool
 */
function os_payment_regenerate_session(): bool
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return false;
    }

    return session_regenerate_id(true);
}

/**
 * Performs a conservative authorization check.
 *
 * The role/privilege must come from trusted server-side session state.
 * Never call this using a role supplied by the browser.
 *
 * @param string $requiredPrivilege
 * @param array<string,mixed> $session
 * @return bool
 */
function os_payment_authorized(
    string $requiredPrivilege,
    array $session
): bool {
    if (
        $requiredPrivilege === ''
        || !isset($session['privileges'])
        || !is_array($session['privileges'])
    ) {
        return false;
    }

    foreach ($session['privileges'] as $privilege) {
        if (
            is_string($privilege)
            && os_payment_secure_equals(
                $requiredPrivilege,
                $privilege
            )
        ) {
            return true;
        }
    }

    return false;
}

/* ------------------------------------------------------------------------- */
/* Brute-force protection primitives                                         */
/* ------------------------------------------------------------------------- */

/**
 * Creates a privacy-preserving identifier for rate limiting.
 *
 * Do not use raw IP addresses as public identifiers or expose this value.
 *
 * A production distributed limiter should preferably perform this operation
 * server-side using Redis/database/WAF infrastructure.
 *
 * @param string $identifier
 * @return string|null
 */
function os_payment_rate_limit_key(
    string $identifier
): ?string {
    if (
        $identifier === ''
        || strlen($identifier) > 512
    ) {
        return null;
    }

    $secret = os_payment_get_key();

    if ($secret === null) {
        return null;
    }

    return hash_hmac(
        'sha256',
        $identifier,
        $secret
    );
}

/**
 * Constant configuration describing recommended authentication throttling.
 *
 * The actual counter must be atomic and shared across application instances.
 *
 * @return array<string,int>
 */
function os_payment_rate_limit_policy(): array
{
    return [
        'max_attempts'
            => OS_PAYMENT_MAX_AUTH_ATTEMPTS_PER_WINDOW,
        'window_seconds'
            => OS_PAYMENT_AUTH_WINDOW_SECONDS,
    ];
}

/* ------------------------------------------------------------------------- */
/* Sensitive-data redaction                                                  */
/* ------------------------------------------------------------------------- */

/**
 * Produces a safe placeholder for sensitive data.
 *
 * Never log:
 * - passwords
 * - password hashes
 * - payment-cookie contents
 * - session IDs
 * - access tokens
 * - refresh tokens
 * - encryption keys
 * - payment credentials
 *
 * @param mixed $value
 * @return string
 */
function os_payment_redact(mixed $value): string
{
    if (!is_string($value) || $value === '') {
        return '[REDACTED]';
    }

    return '[REDACTED]';
}

/**
 * Returns a generic authentication failure.
 *
 * Avoids username/account enumeration through different error messages.
 *
 * @return false
 */
function os_payment_authentication_failure(): bool
{
    return false;
}

/* ------------------------------------------------------------------------- */
/* Security headers                                                          */
/* ------------------------------------------------------------------------- */

/**
 * Sends restrictive response headers.
 *
 * Call before any response body is emitted.
 *
 * @return void
 */
function os_payment_send_security_headers(): void
{
    if (headers_sent()) {
        return;
    }

    header(
        'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
    );
    header('Pragma: no-cache');
    header('Expires: 0');

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
        'Permissions-Policy: geolocation=(), microphone=(), camera=()'
    );

    header(
        'Content-Security-Policy: ' .
        "default-src 'self'; " .
        "base-uri 'self'; " .
        "object-src 'none'; " .
        "frame-ancestors 'none'; " .
        "form-action 'self'; " .
        "img-src 'self' data:; " .
        "font-src 'self'; " .
        "connect-src 'self';"
    );

    /*
     * HSTS should only be enabled when HTTPS is guaranteed for the entire
     * host/domain and subdomain policy has been intentionally verified.
     */
    if (os_payment_is_https()) {
        header(
            'Strict-Transport-Security: ' .
            'max-age=31536000; includeSubDomains'
        );
    }
}

/* ------------------------------------------------------------------------- */
/* CSRF helper                                                               */
/* ------------------------------------------------------------------------- */

/**
 * Generates a CSRF token for a server-side session.
 *
 * CSRF tokens must never be derived from predictable values.
 *
 * @return string|null
 */
function os_payment_csrf_token(): ?string
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return null;
    }

    if (
        isset($_SESSION['csrf_token'])
        && is_string($_SESSION['csrf_token'])
        && strlen($_SESSION['csrf_token']) >= 32
    ) {
        return $_SESSION['csrf_token'];
    }

    $random = os_payment_random_bytes(32);

    if ($random === null) {
        return null;
    }

    $_SESSION['csrf_token'] =
        os_payment_base64url_encode($random);

    return $_SESSION['csrf_token'];
}

/**
 * Validates a CSRF token using a constant-time comparison.
 *
 * @param mixed $provided
 * @return bool
 */
function os_payment_verify_csrf(mixed $provided): bool
{
    if (
        session_status() !== PHP_SESSION_ACTIVE
        || !isset($_SESSION['csrf_token'])
        || !is_string($_SESSION['csrf_token'])
        || !is_string($provided)
    ) {
        return false;
    }

    if (
        strlen($provided) < 32
        || strlen($provided) > 512
    ) {
        return false;
    }

    return os_payment_secure_equals(
        $_SESSION['csrf_token'],
        $provided
    );
}

/* ------------------------------------------------------------------------- */
/* Legacy compatibility intentionally removed                                */
/* ------------------------------------------------------------------------- */

/**
 * Legacy plaintext payment cookies are intentionally unsupported.
 *
 * This function exists only as a compatibility-safe stub so callers cannot
 * accidentally reintroduce the old trust model.
 *
 * @return int
 */
function os_payment_get_legacy_cookie(): int
{
    return 0;
}
