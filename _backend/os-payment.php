<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

/**
 * Security-focused payment-cookie implementation.
 *
 * Security properties:
 * - Payment values are never stored in plaintext.
 * - Cookie contents are authenticated and encrypted with libsodium.
 * - Invalid/tampered cookies fail closed.
 * - Cookie values are opaque and URL-safe.
 * - Cookie names do not disclose the release identifier.
 * - Cookies are HttpOnly, Secure and SameSite=Strict.
 * - No legacy plaintext payment cookie is trusted.
 * - Cryptographic comparisons/decryption are performed by libsodium.
 * - The encryption key must come from trusted server-side configuration.
 *
 * IMPORTANT:
 * The payment cookie is not an authentication credential and must not be
 * used as proof of user identity or authorization. Authorization must be
 * enforced independently by the application/server.
 */

const OS_PAYMENT_MAX_VERSION_LENGTH = 128;
const OS_PAYMENT_MAX_COOKIE_VALUE_LENGTH = 4096;
const OS_PAYMENT_COOKIE_LIFETIME = 31536000;

const OS_PAYMENT_COOKIE_PREFIX = '__Host-os_payment_';
const OS_PAYMENT_CIPHER_VERSION = 1;

/**
 * Returns the maximum supported payment amount.
 *
 * @return int
 */
function os_payment_max_amount(): int
{
    return PHP_INT_MAX;
}

/**
 * Normalizes and validates a release version.
 *
 * @param string $version Release version.
 * @return string|null
 */
function os_payment_normalize_version(string $version): ?string
{
    $version = trim($version);

    if (
        $version === ''
        || strlen($version) > OS_PAYMENT_MAX_VERSION_LENGTH
        || preg_match(
            '/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/',
            $version
        ) !== 1
    ) {
        return null;
    }

    return $version;
}

/**
 * Converts binary data to unpadded base64url.
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
 * Decodes unpadded base64url data.
 *
 * @param string $value
 * @return string|null
 */
function os_payment_base64url_decode(string $value): ?string
{
    if (
        $value === ''
        || strlen($value) > OS_PAYMENT_MAX_COOKIE_VALUE_LENGTH
        || preg_match('/\A[A-Za-z0-9_-]+\z/', $value) !== 1
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
 * Obtains the server-side encryption key.
 *
 * The key must be exactly 32 cryptographically random bytes.
 *
 * Supported configuration:
 *   $config['payment_cookie_key']
 *
 * The value may be:
 *   - raw 32-byte binary data
 *   - 64-character hexadecimal
 *   - 43/44-character base64 representation
 *
 * An environment variable PAYMENT_COOKIE_KEY may also be used.
 *
 * @return string|null
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

        if (is_string($environmentKey) && $environmentKey !== '') {
            $configuredKey = $environmentKey;
        }
    }

    if (!is_string($configuredKey) || $configuredKey === '') {
        return null;
    }

    /*
     * Prefer hexadecimal because it avoids ambiguity between textual
     * and binary representations.
     */
    if (
        strlen($configuredKey) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES * 2
        && ctype_xdigit($configuredKey)
    ) {
        $key = hex2bin($configuredKey);

        return $key === false ? null : $key;
    }

    /*
     * Accept standard base64 configuration as an operational convenience.
     * Strict decoding prevents malformed secrets from being accepted.
     */
    $decoded = base64_decode($configuredKey, true);

    if (
        $decoded !== false
        && strlen($decoded) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES
    ) {
        return $decoded;
    }

    /*
     * Raw binary keys are accepted only when they already have the exact
     * required size.
     */
    if (strlen($configuredKey) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
        return $configuredKey;
    }

    return null;
}

/**
 * Generates a deterministic, non-sensitive cookie name.
 *
 * The release version is hashed so that the cookie name does not disclose
 * the actual release identifier.
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

    $identifier = hash(
        'sha256',
        $version,
        true
    );

    return OS_PAYMENT_COOKIE_PREFIX
        . os_payment_base64url_encode($identifier);
}

/**
 * Determines whether the request is actually HTTPS.
 *
 * Proxy-controlled headers are deliberately ignored.
 *
 * @return bool
 */
function os_payment_is_https(): bool
{
    return isset($_SERVER['HTTPS'])
        && strtolower((string) $_SERVER['HTTPS']) === 'on';
}

/**
 * Parses a payment amount.
 *
 * @param mixed $value
 * @return int|null
 */
function os_payment_parse_amount(mixed $value): ?int
{
    if (!is_string($value)) {
        return null;
    }

    if (
        $value === ''
        || strlen($value) > 19
        || preg_match('/\A(?:0|[1-9][0-9]*)\z/', $value) !== 1
    ) {
        return null;
    }

    /*
     * Avoid implicit integer overflow and platform-dependent coercion.
     */
    if (
        strlen($value) > strlen((string) PHP_INT_MAX)
        || (
            strlen($value) === strlen((string) PHP_INT_MAX)
            && strcmp($value, (string) PHP_INT_MAX) > 0
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

/**
 * Encrypts and authenticates the payment amount.
 *
 * Format:
 *   version || nonce || ciphertext
 *
 * Sodium secretbox provides authenticated encryption, preventing both
 * disclosure and undetected modification of the amount.
 *
 * @param int $amount
 * @return string|null
 */
function os_payment_encrypt_amount(int $amount): ?string
{
    $key = os_payment_get_key();

    if ($key === null) {
        return null;
    }

    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

    $plaintext = json_encode(
        [
            'v' => OS_PAYMENT_CIPHER_VERSION,
            'amount' => (string) $amount,
        ],
        JSON_THROW_ON_ERROR
        | JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );

    try {
        $ciphertext = sodium_crypto_secretbox(
            $plaintext,
            $nonce,
            $key
        );
    } catch (Throwable) {
        return null;
    }

    return os_payment_base64url_encode(
        chr(OS_PAYMENT_CIPHER_VERSION)
        . $nonce
        . $ciphertext
    );
}

/**
 * Decrypts and validates a payment amount.
 *
 * Invalid, forged, malformed or obsolete cookies return null.
 *
 * @param mixed $value
 * @return int|null
 */
function os_payment_decrypt_amount(mixed $value): ?int
{
    if (!is_string($value)) {
        return null;
    }

    $decoded = os_payment_base64url_decode($value);

    if ($decoded === null) {
        return null;
    }

    $minimumLength =
        1
        + SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
        + SODIUM_CRYPTO_SECRETBOX_MACBYTES;

    if (strlen($decoded) < $minimumLength) {
        return null;
    }

    $version = ord($decoded[0]);

    if ($version !== OS_PAYMENT_CIPHER_VERSION) {
        return null;
    }

    $nonce = substr(
        $decoded,
        1,
        SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
    );

    $ciphertext = substr(
        $decoded,
        1 + SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
    );

    if ($nonce === false || $ciphertext === false) {
        return null;
    }

    $key = os_payment_get_key();

    if ($key === null) {
        return null;
    }

    try {
        /*
         * sodium_crypto_secretbox_open verifies the authentication tag
         * before returning plaintext. No application-level equality
         * comparison of secrets is performed.
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
        || ($payload['v'] ?? null) !== OS_PAYMENT_CIPHER_VERSION
        || !isset($payload['amount'])
        || !is_string($payload['amount'])
    ) {
        return null;
    }

    return os_payment_parse_amount($payload['amount']);
}

/**
 * Sets the encrypted payment cookie.
 *
 * The function fails closed when HTTPS or the encryption key is unavailable.
 *
 * @param string $version
 * @param int $amount
 * @return bool
 */
function os_payment_setcookie(string $version, int $amount): bool
{
    $version = os_payment_normalize_version($version);

    if (
        $version === null
        || $amount < 0
        || $amount > os_payment_max_amount()
        || !os_payment_is_https()
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
        || strlen($cookieValue) > OS_PAYMENT_MAX_COOKIE_VALUE_LENGTH
    ) {
        return false;
    }

    /*
     * __Host- cookies:
     * - require Secure
     * - must use Path=/
     * - cannot specify Domain
     *
     * This prevents weaker sibling/subdomain cookie scoping.
     */
    return setcookie(
        $cookieName,
        $cookieValue,
        [
            'expires'  => time() + OS_PAYMENT_COOKIE_LIFETIME,
            'path'     => '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]
    );
}

/**
 * Returns the payment amount for a release.
 *
 * Invalid, forged, expired-format or plaintext legacy cookies are treated
 * exactly like an unpaid release.
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

    /*
     * Never trust arbitrary client-controlled values.
     * Only authenticated ciphertext generated by this application is valid.
     */
    $amount = os_payment_decrypt_amount(
        $_COOKIE[$cookieName]
    );

    return $amount ?? 0;
}

/**
 * Securely removes the payment cookie.
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
            'expires'  => 1,
            'path'     => '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]
    );
}

/**
 * Constant-time comparison helper for application-level secret checks.
 *
 * This function should be used whenever two independently supplied
 * cryptographic values need to be compared.
 *
 * @param string $known
 * @param string $provided
 * @return bool
 */
function os_payment_secure_equals(
    string $known,
    string $provided
): bool {
    if (strlen($known) !== strlen($provided)) {
        /*
         * hash_equals itself safely handles different lengths, while still
         * avoiding the unsafe "==" / "===" comparison of secrets.
         */
        return hash_equals($known, $provided);
    }

    return hash_equals($known, $provided);
}

/**
 * Generates a cryptographically secure opaque token suitable for use as
 * a server-side payment/session reference.
 *
 * The token itself contains no payment information.
 *
 * @return string
 */
function os_payment_generate_token(): string
{
    return os_payment_base64url_encode(
        random_bytes(32)
    );
}

/**
 * Recommended password hashing helper for authentication code elsewhere
 * in the application.
 *
 * Argon2id is preferred. Bcrypt is retained as a compatibility fallback.
 *
 * @param string $password
 * @return string|null
 */
function os_payment_password_hash(string $password): ?string
{
    if ($password === '') {
        return null;
    }

    if (defined('PASSWORD_ARGON2ID')) {
        return password_hash(
            $password,
            PASSWORD_ARGON2ID,
            [
                'memory_cost' => 65536,
                'time_cost'   => 4,
                'threads'     => 2,
            ]
        );
    }

    return password_hash(
        $password,
        PASSWORD_BCRYPT,
        [
            'cost' => 12,
        ]
    );
}

/**
 * Verifies a password against a previously generated password hash.
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
        || $hash === ''
    ) {
        return false;
    }

    return password_verify($password, $hash);
}

/**
 * Indicates whether a stored password should be rehashed.
 *
 * This allows migration to stronger Argon2id parameters without exposing
 * password material.
 *
 * @param string $hash
 * @return bool
 */
function os_payment_password_needs_rehash(string $hash): bool
{
    if (defined('PASSWORD_ARGON2ID')) {
        return password_needs_rehash(
            $hash,
            PASSWORD_ARGON2ID,
            [
                'memory_cost' => 65536,
                'time_cost'   => 4,
                'threads'     => 2,
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
 * Prevents accidental disclosure of sensitive authentication/payment data
 * through application logging.
 *
 * Never pass passwords, payment cookie values, session identifiers or
 * encryption keys to log functions.
 *
 * @param mixed $value
 * @return string
 */
function os_payment_redact(mixed $value): string
{
    if (!is_string($value) || $value === '') {
        return '[REDACTED]';
    }

    return '[REDACTED:' . strlen($value) . ']';
}

