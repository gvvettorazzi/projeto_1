<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

/*
 * SECURITY-HARDENED PAYMENT STATE
 *
 * Design principles:
 *
 * - Client-controlled payment values are NEVER trusted.
 * - Payment state is authenticated and encrypted with libsodium.
 * - Plaintext legacy payment cookies are rejected.
 * - Cookie names do not reveal release identifiers.
 * - __Host- cookies prevent Domain/subdomain cookie injection.
 * - HTTPS is mandatory.
 * - HttpOnly + Secure + SameSite=Strict are enforced.
 * - Passwords use Argon2id, with bcrypt only as a compatibility fallback.
 * - Secret comparisons use hash_equals().
 * - CSRF tokens use CSPRNG and constant-time comparison.
 * - Sessions use strict cookie settings and regeneration.
 * - Authorization uses server-side privileges only.
 * - Authentication failures are intentionally generic.
 * - Rate limiting primitives are provided, but distributed rate limiting
 *   MUST be enforced by the authentication/API layer as well.
 * - Sensitive values are never returned by error helpers.
 * - Security headers are restrictive by default.
 *
 * IMPORTANT:
 * No PHP file can "block all vulnerabilities". Security is a system
 * property. Database access, authorization middleware, reverse proxies,
 * TLS configuration, dependency versions, filesystem permissions, deployment,
 * payment-provider verification and infrastructure rate limiting must also
 * be hardened.
 *
 * OWASP guidance recommends:
 * - Argon2id for password storage.
 * - Secure, server-side session management.
 * - Secure/HttpOnly/SameSite cookies.
 * - Session ID regeneration after authentication/privilege changes.
 * - Defense-in-depth against brute force.
 * - Generic authentication errors.
 * - Reauthentication for sensitive operations.
 *
 * References:
 * OWASP Authentication Cheat Sheet
 * OWASP Session Management Cheat Sheet
 */

/* ==========================================================================
 * CONSTANTS
 * ========================================================================== */

const OS_PAYMENT_MAX_VERSION_LENGTH = 128;
const OS_PAYMENT_MAX_COOKIE_VALUE_LENGTH = 4096;

/*
 * Payment state should generally have a much shorter lifetime than a
 * traditional persistent preference. Kept at the original one-year value
 * for functional compatibility.
 */
const OS_PAYMENT_COOKIE_LIFETIME = 31536000;

const OS_PAYMENT_COOKIE_PREFIX = '__Host-os_payment_';

const OS_PAYMENT_CRYPTO_VERSION = 1;

/*
 * Password policy.
 *
 * OWASP/NIST guidance favors long passwords/passphrases over composition
 * rules. Do not silently truncate passwords.
 */
const OS_PAYMENT_PASSWORD_MIN_LENGTH = 15;
const OS_PAYMENT_PASSWORD_MAX_BYTES = 1024;

/*
 * Argon2id parameters.
 *
 * These are intentionally configurable through constants so they can be
 * benchmarked and increased on production infrastructure.
 */
const OS_PAYMENT_ARGON2_MEMORY_COST = 19456;
const OS_PAYMENT_ARGON2_TIME_COST = 2;
const OS_PAYMENT_ARGON2_THREADS = 1;

const OS_PAYMENT_BCRYPT_COST = 12;

/*
 * Brute-force protection policy.
 *
 * This file only defines policy. Actual distributed counters should be
 * implemented using Redis/database/WAF/API-gateway infrastructure.
 */
const OS_PAYMENT_AUTH_MAX_ATTEMPTS = 5;
const OS_PAYMENT_AUTH_WINDOW_SECONDS = 900;

/*
 * Session inactivity / absolute lifetimes.
 */
const OS_PAYMENT_SESSION_IDLE_TIMEOUT = 1800;
const OS_PAYMENT_SESSION_ABSOLUTE_TIMEOUT = 43200;

/*
 * Maximum request sizes accepted by helper functions.
 */
const OS_PAYMENT_MAX_TOKEN_LENGTH = 4096;
const OS_PAYMENT_MAX_IDENTIFIER_LENGTH = 512;

/* ==========================================================================
 * HTTPS / TRANSPORT
 * ========================================================================== */

/**
 * Determines whether the application is operating over HTTPS.
 *
 * Do not trust arbitrary X-Forwarded-Proto headers here.
 *
 * If the application is behind a reverse proxy, TLS termination must be
 * configured so that HTTPS is established and enforced by trusted
 * infrastructure before reaching this application.
 */
function os_payment_is_https(): bool
{
    return isset($_SERVER['HTTPS'])
        && strtolower((string) $_SERVER['HTTPS']) === 'on';
}

/**
 * Refuse security-sensitive operations over HTTP.
 */
function os_payment_require_https(): bool
{
    return os_payment_is_https();
}

/* ==========================================================================
 * RANDOMNESS / ENCODING
 * ========================================================================== */

/**
 * Generates cryptographically secure random bytes.
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
 * Encodes binary data using Base64URL without padding.
 */
function os_payment_base64url_encode(string $data): string
{
    return rtrim(
        strtr(base64_encode($data), '+/', '-_'),
        '='
    );
}

/**
 * Strict Base64URL decoder.
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
 * Constant-time comparison for secrets.
 */
function os_payment_secure_equals(
    string $known,
    string $provided
): bool {
    return hash_equals($known, $provided);
}

/* ==========================================================================
 * RELEASE VALIDATION
 * ========================================================================== */

/**
 * Validates a release version.
 */
function os_payment_normalize_version(
    string $version
): ?string {
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
 * The release version itself is not exposed.
 */
function os_payment_cookie_name(
    string $version
): ?string {
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

/* ==========================================================================
 * SERVER-SIDE CRYPTOGRAPHIC KEY
 * ========================================================================== */

/**
 * Retrieves the encryption key.
 *
 * Production recommendation:
 * Store this in a dedicated secret manager/KMS/Vault/environment secret,
 * never in source control and never in a client-accessible file.
 *
 * Accepted:
 * - 64-character hexadecimal key
 * - Base64 containing exactly 32 bytes
 * - raw 32-byte binary key
 */
function os_payment_get_key(): ?string
{
    global $config;

    $configuredKey = null;

    if (
        is_array($config ?? null)
        && isset($config['payment_cookie_key'])
        && is_string($config['payment_cookie_key'])
    ) {
        $configuredKey = $config['payment_cookie_key'];
    }

    if ($configuredKey === null || $configuredKey === '') {
        $environmentKey = getenv('PAYMENT_COOKIE_KEY');

        if (
            is_string($environmentKey)
            && $environmentKey !== ''
        ) {
            $configuredKey = $environmentKey;
        }
    }

    if (!is_string($configuredKey) || $configuredKey === '') {
        return null;
    }

    /*
     * Preferred representation.
     */
    if (
        strlen($configuredKey) === 64
        && ctype_xdigit($configuredKey)
    ) {
        $decoded = hex2bin($configuredKey);

        if (
            $decoded !== false
            && strlen($decoded)
                === SODIUM_CRYPTO_SECRETBOX_KEYBYTES
        ) {
            return $decoded;
        }
    }

    /*
     * Base64 representation.
     */
    $decoded = base64_decode(
        $configuredKey,
        true
    );

    if (
        $decoded !== false
        && strlen($decoded)
            === SODIUM_CRYPTO_SECRETBOX_KEYBYTES
    ) {
        return $decoded;
    }

    /*
     * Raw binary representation.
     */
    if (
        strlen($configuredKey)
        === SODIUM_CRYPTO_SECRETBOX_KEYBYTES
    ) {
        return $configuredKey;
    }

    return null;
}

/**
 * Generates a new 256-bit payment encryption key.
 *
 * The returned value should be provisioned into a secret manager.
 */
function os_payment_generate_key(): ?string
{
    $key = os_payment_random_bytes(
        SODIUM_CRYPTO_SECRETBOX_KEYBYTES
    );

    return $key === null
        ? null
        : bin2hex($key);
}

/* ==========================================================================
 * PAYMENT AMOUNT VALIDATION
 * ========================================================================== */

/**
 * Parses an amount without implicit type coercion.
 */
function os_payment_parse_amount(
    mixed $value
): ?int {
    if (!is_string($value)) {
        return null;
    }

    /*
     * Only canonical unsigned decimal integers.
     *
     * Rejected:
     *   "10abc"
     *   "10.5"
     *   "+10"
     *   "-1"
     *   " 10 "
     *   "1e3"
     *   hexadecimal values
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

    /*
     * Explicit overflow protection.
     */
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

    return $amount === false
        ? null
        : $amount;
}

/* ==========================================================================
 * AUTHENTICATED ENCRYPTION
 * ========================================================================== */

/**
 * Encrypts payment state using authenticated encryption.
 *
 * Sodium secretbox provides:
 * - confidentiality
 * - integrity
 * - authenticity
 *
 * An attacker who modifies the cookie cannot produce valid payment state
 * without possession of the server-side key.
 */
function os_payment_encrypt_amount(
    int $amount
): ?string {
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
 */
function os_payment_decrypt_amount(
    mixed $value
): ?int {
    if (!is_string($value)) {
        return null;
    }

    if (
        $value === ''
        || strlen($value)
            > OS_PAYMENT_MAX_COOKIE_VALUE_LENGTH
    ) {
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
         * Authentication is verified by libsodium before plaintext is
         * returned.
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

/* ==========================================================================
 * PAYMENT COOKIE API
 * ========================================================================== */

/**
 * Writes the secure payment cookie.
 *
 * The operation fails closed unless HTTPS and cryptographic configuration
 * are available.
 */
function os_payment_setcookie(
    string $version,
    int $amount
): bool {
    $version = os_payment_normalize_version($version);

    if (
        $version === null
        || $amount < 0
        || !os_payment_require_https()
        || !function_exists('sodium_crypto_secretbox')
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
     * __Host- cookie requirements:
     *
     * Secure
     * Path=/
     * no Domain
     *
     * This protects against many subdomain cookie-injection scenarios.
     */
    return setcookie(
        $cookieName,
        $cookieValue,
        [
            'expires' =>
                time() + OS_PAYMENT_COOKIE_LIFETIME,
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
 * IMPORTANT:
 * The browser is not trusted.
 */
function os_payment_getcookie(
    string $version
): int {
    $version = os_payment_normalize_version($version);

    if ($version === null) {
        return 0;
    }

    $cookieName = os_payment_cookie_name($version);

    if (
        $cookieName === null
        || !array_key_exists(
            $cookieName,
            $_COOKIE
        )
    ) {
        return 0;
    }

    $amount = os_payment_decrypt_amount(
        $_COOKIE[$cookieName]
    );

    /*
     * Fail closed.
     */
    return $amount ?? 0;
}

/**
 * Removes the secure payment cookie.
 */
function os_payment_clearcookie(
    string $version
): bool {
    $version = os_payment_normalize_version($version);

    if (
        $version === null
        || !os_payment_require_https()
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

/**
 * Legacy plaintext payment cookies are NEVER trusted.
 *
 * Returning zero ensures an attacker cannot bypass the authenticated cookie
 * format by manipulating an old cookie.
 */
function os_payment_get_legacy_cookie(): int
{
    return 0;
}

/* ==========================================================================
 * PASSWORD SECURITY
 * ========================================================================== */

/**
 * Validates password size.
 *
 * No character-composition restrictions are imposed.
 */
function os_payment_password_is_valid(
    string $password
): bool {
    $length = strlen($password);

    return $length >= OS_PAYMENT_PASSWORD_MIN_LENGTH
        && $length <= OS_PAYMENT_PASSWORD_MAX_BYTES;
}

/**
 * Creates an Argon2id password hash.
 *
 * Bcrypt is only a compatibility fallback.
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

    return is_string($hash)
        ? $hash
        : null;
}

/**
 * Securely verifies a password.
 *
 * Never compare password hashes manually.
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
 * Determines whether an existing password hash should be upgraded.
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

/* ==========================================================================
 * SESSION SECURITY
 * ========================================================================== */

/**
 * Configures PHP's native session mechanism.
 *
 * Call BEFORE session_start().
 */
function os_payment_configure_session(): bool
{
    if (!os_payment_require_https()) {
        return false;
    }

    /*
     * Prevent session IDs from appearing in URLs.
     */
    ini_set(
        'session.use_only_cookies',
        '1'
    );

    ini_set(
        'session.use_trans_sid',
        '0'
    );

    /*
     * Reject attacker-supplied uninitialized session IDs.
     */
    ini_set(
        'session.use_strict_mode',
        '1'
    );

    /*
     * Protect the cookie from JavaScript.
     */
    ini_set(
        'session.cookie_httponly',
        '1'
    );

    /*
     * HTTPS only.
     */
    ini_set(
        'session.cookie_secure',
        '1'
    );

    /*
     * Reduce session lifetime.
     */
    ini_set(
        'session.gc_maxlifetime',
        (string) OS_PAYMENT_SESSION_ABSOLUTE_TIMEOUT
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
 * Regenerates the session identifier.
 *
 * Must be called immediately after authentication and privilege changes.
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
 * Logs the user out securely.
 */
function os_payment_logout(): bool
{
    if (
        session_status()
        !== PHP_SESSION_ACTIVE
    ) {
        return false;
    }

    /*
     * Remove server-side state first.
     */
    $_SESSION = [];

    /*
     * Expire the client-side session cookie.
     */
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            [
                'expires' => 1,
                'path' =>
                    $params['path'] ?? '/',
                'domain' =>
                    $params['domain'] ?? '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict',
            ]
        );
    }

    return session_destroy();
}

/**
 * Checks server-side session freshness.
 */
function os_payment_session_is_valid(): bool
{
    if (
        session_status()
        !== PHP_SESSION_ACTIVE
    ) {
        return false;
    }

    $now = time();

    if (
        isset($_SESSION['created_at'])
        && is_int($_SESSION['created_at'])
        && (
            $now - $_SESSION['created_at']
            > OS_PAYMENT_SESSION_ABSOLUTE_TIMEOUT
        )
    ) {
        return false;
    }

    if (
        isset($_SESSION['last_activity'])
        && is_int($_SESSION['last_activity'])
        && (
            $now - $_SESSION['last_activity']
            > OS_PAYMENT_SESSION_IDLE_TIMEOUT
        )
    ) {
        return false;
    }

    /*
     * Do not accept client-controlled timestamps.
     */
    if (!isset($_SESSION['created_at'])) {
        $_SESSION['created_at'] = $now;
    }

    $_SESSION['last_activity'] = $now;

    return true;
}

/* ==========================================================================
 * AUTHORIZATION
 * ========================================================================== */

/**
 * Checks a privilege stored in trusted server-side session state.
 *
 * Never pass a role/privilege obtained from:
 * - $_GET
 * - $_POST
 * - $_COOKIE
 * - request headers
 * - JSON body
 *
 * Authorization data must originate from trusted server-side state.
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

/**
 * Requires authentication AND a specific privilege.
 */
function os_payment_require_privilege(
    string $requiredPrivilege
): bool {
    if (
        session_status()
        !== PHP_SESSION_ACTIVE
    ) {
        return false;
    }

    if (!os_payment_session_is_valid()) {
        return false;
    }

    return os_payment_authorized(
        $requiredPrivilege,
        $_SESSION
    );
}

/* ==========================================================================
 * CSRF PROTECTION
 * ========================================================================== */

/**
 * Creates/retrieves a per-session CSRF token.
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

    $random = os_payment_random_bytes(32);

    if ($random === null) {
        return null;
    }

    $token = os_payment_base64url_encode(
        $random
    );

    $_SESSION['csrf_token'] = $token;

    return $token;
}

/**
 * Validates a CSRF token.
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

/* ==========================================================================
 * BRUTE FORCE / RATE LIMITING
 * ========================================================================== */

/**
 * Creates a privacy-preserving rate-limit key.
 *
 * The raw identifier should never be logged or exposed.
 *
 * A production implementation must use an atomic shared store such as
 * Redis/database infrastructure rather than PHP process memory.
 */
function os_payment_rate_limit_key(
    string $identifier
): ?string {
    if (
        $identifier === ''
        || strlen($identifier)
            > OS_PAYMENT_MAX_IDENTIFIER_LENGTH
    ) {
        return null;
    }

    $key = os_payment_get_key();

    if ($key === null) {
        return null;
    }

    return hash_hmac(
        'sha256',
        $identifier,
        $key
    );
}

/**
 * Returns the authentication rate-limit policy.
 */
function os_payment_rate_limit_policy(): array
{
    return [
        'max_attempts'
            => OS_PAYMENT_AUTH_MAX_ATTEMPTS,
        'window_seconds'
            => OS_PAYMENT_AUTH_WINDOW_SECONDS,
    ];
}

/**
 * Generates an opaque authentication token.
 *
 * Do not put identity/privilege information inside the token.
 */
function os_payment_generate_auth_token(): ?string
{
    $random = os_payment_random_bytes(32);

    if ($random === null) {
        return null;
    }

    return os_payment_base64url_encode(
        $random
    );
}

/* ==========================================================================
 * AUTHENTICATION FAILURE / INFORMATION DISCLOSURE
 * ========================================================================== */

/**
 * Generic authentication failure.
 *
 * The same result should be used for:
 * - unknown account
 * - wrong password
 * - disabled account
 * - invalid credential
 *
 * This reduces account enumeration.
 */
function os_payment_authentication_failure(): bool
{
    return false;
}

/**
 * Redacts sensitive information.
 *
 * Never log the underlying value.
 */
function os_payment_redact(
    mixed $value
): string {
    return '[REDACTED]';
}

/* ==========================================================================
 * SECURITY HEADERS
 * ========================================================================== */

/**
 * Sends defensive HTTP security headers.
 *
 * Must be called before output is generated.
 */
function os_payment_send_security_headers(): void
{
    if (headers_sent()) {
        return;
    }

    /*
     * Sensitive/payment responses should not be cached.
     */
    header(
        'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
    );

    header('Pragma: no-cache');
    header('Expires: 0');

    /*
     * MIME sniffing protection.
     */
    header(
        'X-Content-Type-Options: nosniff'
    );

    /*
     * Clickjacking protection.
     */
    header(
        'X-Frame-Options: DENY'
    );

    /*
     * Avoid leaking URLs through Referer.
     */
    header(
        'Referrer-Policy: no-referrer'
    );

    /*
     * Disable unnecessary browser capabilities.
     */
    header(
        'Permissions-Policy: ' .
        'camera=(), ' .
        'microphone=(), ' .
        'geolocation=(), ' .
        'payment=(), ' .
        'usb=(), ' .
        'bluetooth=()'
    );

    /*
     * Strict CSP.
     *
     * If the surrounding application legitimately requires inline scripts,
     * replace this with nonce-based CSP rather than adding unsafe-inline.
     */
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
        "connect-src 'self';"
    );

    /*
     * HSTS is safe only when HTTPS is guaranteed for the entire host and
     * all included subdomains.
     */
    if (os_payment_is_https()) {
        header(
            'Strict-Transport-Security: ' .
            'max-age=31536000; includeSubDomains'
        );
    }
}

/* ==========================================================================
 * HTTP METHOD / REQUEST PROTECTION
 * ========================================================================== */

/**
 * Strictly validates an HTTP method.
 *
 * Use this before state-changing operations.
 */
function os_payment_require_method(
    string $expectedMethod
): bool {
    $expectedMethod = strtoupper(
        trim($expectedMethod)
    );

    $actualMethod = strtoupper(
        (string) ($_SERVER['REQUEST_METHOD'] ?? '')
    );

    if (
        $expectedMethod === ''
        || $actualMethod === ''
    ) {
        return false;
    }

    return os_payment_secure_equals(
        $expectedMethod,
        $actualMethod
    );
}

/**
 * Indicates whether a request is considered state-changing.
 */
function os_payment_is_state_changing_request(): bool
{
    $method = strtoupper(
        (string) ($_SERVER['REQUEST_METHOD'] ?? '')
    );

    return in_array(
        $method,
        [
            'POST',
            'PUT',
            'PATCH',
            'DELETE',
        ],
        true
    );
}

/* ==========================================================================
 * SECURE AUTHENTICATION HELPER
 * ========================================================================== */

/**
 * Performs the local password verification step.
 *
 * The caller MUST:
 * - retrieve the user record server-side;
 * - apply distributed rate limiting BEFORE expensive verification;
 * - use a generic failure response;
 * - regenerate the session after success;
 * - invalidate previous sessions where policy requires it.
 */
function os_payment_verify_credentials(
    string $password,
    string $storedHash
): bool {
    /*
     * Always impose an upper bound before password_verify() to reduce
     * resource-exhaustion risk.
     */
    if (
        $password === ''
        || strlen($password)
            > OS_PAYMENT_PASSWORD_MAX_BYTES
        || $storedHash === ''
        || strlen($storedHash) > 1024
    ) {
        return false;
    }

    /*
     * password_verify() is the correct API. Never use:
     *
     * $password === $storedHash
     * md5()
     * sha1()
     * hash('sha256', $password)
     *
     * for password storage.
     */
    return os_payment_password_verify(
        $password,
        $storedHash
    );
}

/* ==========================================================================
 * SENSITIVE OPERATION REAUTHENTICATION
 * ========================================================================== */

/**
 * Requires a recent successful authentication.
 *
 * Sensitive operations should require reauthentication even when an active
 * session exists.
 */
function os_payment_require_recent_auth(
    int $maxAgeSeconds = 900
): bool {
    if (
        $maxAgeSeconds < 1
        || session_status()
            !== PHP_SESSION_ACTIVE
    ) {
        return false;
    }

    if (
        !isset($_SESSION['authenticated_at'])
        || !is_int($_SESSION['authenticated_at'])
    ) {
        return false;
    }

    return time()
        - $_SESSION['authenticated_at']
        <= $maxAgeSeconds;
}

/* ==========================================================================
 * FAIL-CLOSED UTILITIES
 * ========================================================================== */

/**
 * Generic security failure.
 *
 * Never expose cryptographic, database or authentication internals to the
 * client.
 */
function os_payment_fail_closed(): never
{
    http_response_code(403);
    exit;
}
