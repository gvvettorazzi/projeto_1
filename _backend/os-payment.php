<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

/*
 * Security-first payment/authentication helpers.
 *
 * Core security principles:
 * - deny by default;
 * - sensitive payment data remains server-side;
 * - browsers receive only opaque random identifiers;
 * - strict input validation;
 * - constant-time secret comparisons;
 * - Argon2id preferred for password storage;
 * - Bcrypt fallback;
 * - brute-force protection;
 * - session fixation mitigation;
 * - CSRF protection;
 * - least-privilege authorization;
 * - generic authentication/error responses;
 * - sensitive data is never intentionally logged;
 * - secure cookies and HTTPS required for privileged operations.
 */

const OS_PAYMENT_MAX_VERSION_LENGTH = 128;

const OS_PAYMENT_TOKEN_BYTES = 32;
const OS_PAYMENT_MAX_TOKEN_LENGTH = 512;
const OS_PAYMENT_HASH_HEX_LENGTH = 64;

const OS_PAYMENT_COOKIE_LIFETIME = 31_536_000;
const OS_PAYMENT_COOKIE_PREFIX = '__Host-os_payment_';

const OS_PAYMENT_MIN_PASSWORD_LENGTH = 8;
const OS_PAYMENT_MAX_PASSWORD_LENGTH = 1024;
const OS_PAYMENT_BCRYPT_MAX_PASSWORD_BYTES = 72;

const OS_PAYMENT_ARGON2_MEMORY_COST = 19_456;
const OS_PAYMENT_ARGON2_TIME_COST = 2;
const OS_PAYMENT_ARGON2_THREADS = 1;
const OS_PAYMENT_BCRYPT_COST = 12;

const OS_PAYMENT_CSRF_BYTES = 32;

const OS_PAYMENT_MAX_AUTH_ATTEMPTS = 5;
const OS_PAYMENT_AUTH_WINDOW_SECONDS = 900;
const OS_PAYMENT_AUTH_BASE_LOCK_SECONDS = 60;
const OS_PAYMENT_AUTH_MAX_LOCK_SECONDS = 3600;

const OS_PAYMENT_SESSION_AUTH_KEY = 'os_payment_auth';
const OS_PAYMENT_SESSION_CSRF_KEY = 'os_payment_csrf';
const OS_PAYMENT_SESSION_RATE_LIMIT_KEY = 'os_payment_rate_limits';

const OS_PAYMENT_SESSION_IDLE_TIMEOUT = 1800;
const OS_PAYMENT_SESSION_ABSOLUTE_TIMEOUT = 28_800;

const OS_PAYMENT_MAX_IDENTIFIER_LENGTH = 255;
const OS_PAYMENT_MAX_PRIVILEGE_LENGTH = 128;

const OS_PAYMENT_DUMMY_PASSWORD =
    'os-payment-dummy-password-used-only-for-timing-normalization';

/**
 * Normalizes and validates a release identifier.
 */
function os_payment_normalize_version(string $version): ?string
{
    $version = trim($version);

    if (
        $version === ''
        || strlen($version) > OS_PAYMENT_MAX_VERSION_LENGTH
    ) {
        return null;
    }

    if (
        preg_match(
            '/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/D',
            $version
        ) !== 1
    ) {
        return null;
    }

    return $version;
}

/**
 * Encodes binary data using unpadded Base64URL.
 */
function os_payment_base64url_encode(string $value): string
{
    return rtrim(
        strtr(
            base64_encode($value),
            '+/',
            '-_'
        ),
        '='
    );
}

/**
 * Generates an opaque cookie name.
 */
function os_payment_cookie_name(string $version): ?string
{
    $normalizedVersion = os_payment_normalize_version($version);

    if ($normalizedVersion === null) {
        return null;
    }

    $digest = hash(
        'sha256',
        $normalizedVersion,
        true
    );

    return OS_PAYMENT_COOKIE_PREFIX
        . os_payment_base64url_encode($digest);
}

/**
 * Generates a cryptographically secure opaque payment token.
 */
function os_payment_generate_token(): ?string
{
    try {
        return os_payment_base64url_encode(
            random_bytes(OS_PAYMENT_TOKEN_BYTES)
        );
    } catch (Throwable) {
        return null;
    }
}

/**
 * Validates an opaque payment token.
 */
function os_payment_is_valid_token(string $token): bool
{
    if (
        $token === ''
        || strlen($token) > OS_PAYMENT_MAX_TOKEN_LENGTH
    ) {
        return false;
    }

    return preg_match(
        '/\A[A-Za-z0-9_-]+\z/D',
        $token
    ) === 1;
}

/**
 * Hashes a payment token before server-side persistence.
 *
 * Raw tokens must never be persisted.
 */
function os_payment_hash_token(string $token): string
{
    return hash(
        'sha256',
        $token
    );
}

/**
 * Validates a hexadecimal SHA-256 hash.
 */
function os_payment_is_valid_hash(string $hash): bool
{
    return strlen($hash) === OS_PAYMENT_HASH_HEX_LENGTH
        && preg_match(
            '/\A[0-9a-f]{64}\z/D',
            $hash
        ) === 1;
}

/**
 * Performs constant-time comparison of token hashes.
 */
function os_payment_token_matches(
    string $storedHash,
    string $providedHash
): bool {
    if (
        !os_payment_is_valid_hash($storedHash)
        || !os_payment_is_valid_hash($providedHash)
    ) {
        return false;
    }

    return hash_equals(
        $storedHash,
        $providedHash
    );
}

/**
 * Returns the payment-cookie lifetime.
 */
function os_payment_cookie_lifetime(): int
{
    return OS_PAYMENT_COOKIE_LIFETIME;
}

/**
 * Returns secure cookie attributes.
 *
 * @return array{
 *     expires:int,
 *     path:string,
 *     secure:bool,
 *     httponly:bool,
 *     samesite:string
 * }
 */
function os_payment_cookie_options(int $expires): array
{
    return [
        'expires' => $expires,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ];
}

/**
 * Creates a secure payment cookie.
 *
 * Only an opaque identifier may be stored client-side.
 */
function os_payment_setcookie(
    string $version,
    string $token
): bool {
    if (
        !os_payment_is_https()
        || !os_payment_is_valid_token($token)
    ) {
        return false;
    }

    $cookieName = os_payment_cookie_name($version);

    if ($cookieName === null) {
        return false;
    }

    return setcookie(
        $cookieName,
        $token,
        os_payment_cookie_options(
            time() + OS_PAYMENT_COOKIE_LIFETIME
        )
    );
}

/**
 * Retrieves and validates an opaque payment token.
 */
function os_payment_getcookie(string $version): ?string
{
    $cookieName = os_payment_cookie_name($version);

    if ($cookieName === null) {
        return null;
    }

    $token = $_COOKIE[$cookieName] ?? null;

    if (
        !is_string($token)
        || !os_payment_is_valid_token($token)
    ) {
        return null;
    }

    return $token;
}

/**
 * Removes the payment cookie.
 */
function os_payment_clearcookie(string $version): bool
{
    if (!os_payment_is_https()) {
        return false;
    }

    $cookieName = os_payment_cookie_name($version);

    if ($cookieName === null) {
        return false;
    }

    return setcookie(
        $cookieName,
        '',
        os_payment_cookie_options(1)
    );
}

/**
 * Detects whether the request is HTTPS.
 *
 * Client-controlled forwarding headers are deliberately ignored.
 */
function os_payment_is_https(): bool
{
    $https = $_SERVER['HTTPS'] ?? null;

    if (!is_string($https)) {
        return false;
    }

    return in_array(
        strtolower(trim($https)),
        ['on', '1'],
        true
    );
}

/**
 * Validates a password for general processing.
 */
function os_payment_is_valid_password(string $password): bool
{
    $length = strlen($password);

    return $length >= OS_PAYMENT_MIN_PASSWORD_LENGTH
        && $length <= OS_PAYMENT_MAX_PASSWORD_LENGTH;
}

/**
 * Returns the preferred password hashing configuration.
 *
 * @return array{algorithm:string|int,options:array<string,int>}
 */
function os_payment_password_configuration(): array
{
    if (defined('PASSWORD_ARGON2ID')) {
        return [
            'algorithm' => PASSWORD_ARGON2ID,
            'options' => [
                'memory_cost' => OS_PAYMENT_ARGON2_MEMORY_COST,
                'time_cost' => OS_PAYMENT_ARGON2_TIME_COST,
                'threads' => OS_PAYMENT_ARGON2_THREADS,
            ],
        ];
    }

    return [
        'algorithm' => PASSWORD_BCRYPT,
        'options' => [
            'cost' => OS_PAYMENT_BCRYPT_COST,
        ],
    ];
}

/**
 * Securely hashes a password.
 *
 * Argon2id is preferred.
 */
function os_payment_password_hash(string $password): ?string
{
    if (!os_payment_is_valid_password($password)) {
        return null;
    }

    $configuration = os_payment_password_configuration();

    /*
     * Native Bcrypt considers only the first 72 bytes.
     * Reject oversized input rather than silently truncating it.
     */
    if (
        $configuration['algorithm'] === PASSWORD_BCRYPT
        && strlen($password) > OS_PAYMENT_BCRYPT_MAX_PASSWORD_BYTES
    ) {
        return null;
    }

    try {
        $hash = password_hash(
            $password,
            $configuration['algorithm'],
            $configuration['options']
        );
    } catch (Throwable) {
        return null;
    }

    return is_string($hash)
        ? $hash
        : null;
}

/**
 * Performs password verification.
 */
function os_payment_password_verify(
    string $password,
    string $hash
): bool {
    if (
        $password === ''
        || strlen($password) > OS_PAYMENT_MAX_PASSWORD_LENGTH
        || $hash === ''
        || strlen($hash) > OS_PAYMENT_MAX_PASSWORD_LENGTH
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
 * Determines whether a password hash requires upgrading.
 */
function os_payment_password_needs_rehash(string $hash): bool
{
    if (
        $hash === ''
        || strlen($hash) > OS_PAYMENT_MAX_PASSWORD_LENGTH
    ) {
        return false;
    }

    $configuration = os_payment_password_configuration();

    try {
        return password_needs_rehash(
            $hash,
            $configuration['algorithm'],
            $configuration['options']
        );
    } catch (Throwable) {
        return false;
    }
}

/**
 * Validates an authentication/rate-limit identifier.
 */
function os_payment_is_valid_identifier(string $identifier): bool
{
    $length = strlen($identifier);

    return $length > 0
        && $length <= OS_PAYMENT_MAX_IDENTIFIER_LENGTH;
}

/**
 * Returns an optional application secret.
 *
 * Recommended:
 * OS_PAYMENT_APP_SECRET must contain at least 32 random bytes/characters.
 */
function os_payment_application_secret(): ?string
{
    $secret = getenv('OS_PAYMENT_APP_SECRET');

    if (
        !is_string($secret)
        || strlen($secret) < 32
    ) {
        return null;
    }

    return $secret;
}

/**
 * Generates a privacy-preserving server-side rate-limit key.
 */
function os_payment_rate_limit_key(string $identifier): string
{
    $secret = os_payment_application_secret();

    if ($secret !== null) {
        return hash_hmac(
            'sha256',
            $identifier,
            $secret
        );
    }

    return hash(
        'sha256',
        $identifier
    );
}

/**
 * Normalizes stored rate-limit state.
 *
 * @param mixed $state
 * @return array{
 *     attempts:int,
 *     window_started:int,
 *     locked_until:int
 * }
 */
function os_payment_normalize_rate_limit_state(
    mixed $state
): array {
    $now = time();

    if (!is_array($state)) {
        return [
            'attempts' => 0,
            'window_started' => $now,
            'locked_until' => 0,
        ];
    }

    return [
        'attempts' => max(
            0,
            (int) ($state['attempts'] ?? 0)
        ),
        'window_started' => max(
            0,
            (int) ($state['window_started'] ?? $now)
        ),
        'locked_until' => max(
            0,
            (int) ($state['locked_until'] ?? 0)
        ),
    ];
}

/**
 * Returns rate-limit storage state.
 *
 * APCu is preferred when available because session-only rate limiting can
 * be bypassed by starting a new session.
 *
 * @return array{
 *     attempts:int,
 *     window_started:int,
 *     locked_until:int
 * }
 */
function os_payment_rate_limit_state(
    string $identifier
): array {
    $key = os_payment_rate_limit_key($identifier);

    if (os_payment_apcu_available()) {
        $success = false;

        $value = apcu_fetch(
            'os_payment_auth_' . $key,
            $success
        );

        if ($success) {
            return os_payment_normalize_rate_limit_state(
                $value
            );
        }
    }

    if (session_status() === PHP_SESSION_ACTIVE) {
        $limits = $_SESSION[
            OS_PAYMENT_SESSION_RATE_LIMIT_KEY
        ] ?? [];

        if (
            is_array($limits)
            && array_key_exists($key, $limits)
        ) {
            return os_payment_normalize_rate_limit_state(
                $limits[$key]
            );
        }
    }

    return os_payment_normalize_rate_limit_state(null);
}

/**
 * Determines whether APCu can safely be used.
 */
function os_payment_apcu_available(): bool
{
    if (
        !function_exists('apcu_fetch')
        || !function_exists('apcu_store')
        || !filter_var(
            ini_get('apc.enabled'),
            FILTER_VALIDATE_BOOLEAN
        )
    ) {
        return false;
    }

    if (
        PHP_SAPI === 'cli'
        && !filter_var(
            ini_get('apc.enable_cli'),
            FILTER_VALIDATE_BOOLEAN
        )
    ) {
        return false;
    }

    return true;
}

/**
 * Persists rate-limit state.
 *
 * @param array{
 *     attempts:int,
 *     window_started:int,
 *     locked_until:int
 * } $state
 */
function os_payment_save_rate_limit_state(
    string $identifier,
    array $state
): void {
    $key = os_payment_rate_limit_key($identifier);

    $ttl = max(
        OS_PAYMENT_AUTH_WINDOW_SECONDS,
        OS_PAYMENT_AUTH_MAX_LOCK_SECONDS
    ) + 60;

    if (os_payment_apcu_available()) {
        apcu_store(
            'os_payment_auth_' . $key,
            $state,
            $ttl
        );

        return;
    }

    if (session_status() !== PHP_SESSION_ACTIVE) {
        return;
    }

    if (
        !isset($_SESSION[OS_PAYMENT_SESSION_RATE_LIMIT_KEY])
        || !is_array(
            $_SESSION[OS_PAYMENT_SESSION_RATE_LIMIT_KEY]
        )
    ) {
        $_SESSION[OS_PAYMENT_SESSION_RATE_LIMIT_KEY] = [];
    }

    $_SESSION[
        OS_PAYMENT_SESSION_RATE_LIMIT_KEY
    ][$key] = $state;
}

/**
 * Deletes stored rate-limit state.
 */
function os_payment_clear_rate_limit_state(
    string $identifier
): void {
    $key = os_payment_rate_limit_key($identifier);

    if (
        os_payment_apcu_available()
        && function_exists('apcu_delete')
    ) {
        apcu_delete(
            'os_payment_auth_' . $key
        );
    }

    if (
        session_status() === PHP_SESSION_ACTIVE
        && isset(
            $_SESSION[
                OS_PAYMENT_SESSION_RATE_LIMIT_KEY
            ]
        )
        && is_array(
            $_SESSION[
                OS_PAYMENT_SESSION_RATE_LIMIT_KEY
            ]
        )
    ) {
        unset(
            $_SESSION[
                OS_PAYMENT_SESSION_RATE_LIMIT_KEY
            ][$key]
        );
    }
}

/**
 * Determines whether authentication is currently permitted.
 */
function os_payment_rate_limit_allows(
    string $identifier
): bool {
    if (!os_payment_is_valid_identifier($identifier)) {
        return false;
    }

    $state = os_payment_rate_limit_state(
        $identifier
    );

    return $state['locked_until'] <= time();
}

/**
 * Records an authentication failure.
 *
 * Repeated attack windows cause progressively longer lockouts.
 */
function os_payment_rate_limit_failure(
    string $identifier
): void {
    if (!os_payment_is_valid_identifier($identifier)) {
        return;
    }

    $now = time();

    $state = os_payment_rate_limit_state(
        $identifier
    );

    if (
        $state['window_started'] <= 0
        || (
            $now - $state['window_started']
        ) >= OS_PAYMENT_AUTH_WINDOW_SECONDS
    ) {
        $state = [
            'attempts' => 0,
            'window_started' => $now,
            'locked_until' => 0,
        ];
    }

    $state['attempts']++;

    if (
        $state['attempts']
        >= OS_PAYMENT_MAX_AUTH_ATTEMPTS
    ) {
        $excessAttempts = max(
            0,
            $state['attempts']
                - OS_PAYMENT_MAX_AUTH_ATTEMPTS
        );

        $multiplier = 2 ** min(
            $excessAttempts,
            6
        );

        $lockDuration = min(
            OS_PAYMENT_AUTH_BASE_LOCK_SECONDS
                * $multiplier,
            OS_PAYMENT_AUTH_MAX_LOCK_SECONDS
        );

        $state['locked_until'] = $now
            + $lockDuration;
    }

    os_payment_save_rate_limit_state(
        $identifier,
        $state
    );
}

/**
 * Clears authentication failures following a successful login.
 */
function os_payment_rate_limit_success(
    string $identifier
): void {
    if (!os_payment_is_valid_identifier($identifier)) {
        return;
    }

    os_payment_clear_rate_limit_state(
        $identifier
    );
}

/**
 * Performs a dummy password verification to reduce timing differences
 * when no valid account hash is available.
 */
function os_payment_dummy_password_verify(
    string $password
): void {
    static $dummyHash = null;

    if (!is_string($dummyHash)) {
        $generated = password_hash(
            OS_PAYMENT_DUMMY_PASSWORD,
            PASSWORD_BCRYPT,
            [
                'cost' => OS_PAYMENT_BCRYPT_COST,
            ]
        );

        if (!is_string($generated)) {
            return;
        }

        $dummyHash = $generated;
    }

    try {
        password_verify(
            $password,
            $dummyHash
        );
    } catch (Throwable) {
        // Intentionally ignored.
    }
}

/**
 * Returns a generic authentication failure.
 */
function os_payment_authentication_failure(): bool
{
    return false;
}

/**
 * Performs password authentication with brute-force controls.
 *
 * The caller should supply an identifier that combines the account
 * identifier with an appropriate trusted network/client identifier.
 */
function os_payment_authenticate_password(
    string $identifier,
    string $password,
    string $storedHash
): bool {
    if (!os_payment_is_valid_identifier($identifier)) {
        os_payment_dummy_password_verify(
            $password
        );

        return false;
    }

    if (!os_payment_rate_limit_allows($identifier)) {
        os_payment_dummy_password_verify(
            $password
        );

        return false;
    }

    if (
        $storedHash === ''
        || strlen($storedHash) > OS_PAYMENT_MAX_PASSWORD_LENGTH
    ) {
        os_payment_dummy_password_verify(
            $password
        );

        os_payment_rate_limit_failure(
            $identifier
        );

        return false;
    }

    if (
        !os_payment_password_verify(
            $password,
            $storedHash
        )
    ) {
        os_payment_rate_limit_failure(
            $identifier
        );

        return false;
    }

    os_payment_rate_limit_success(
        $identifier
    );

    return true;
}

/**
 * Configures hardened PHP sessions.
 *
 * Must execute before session_start().
 */
function os_payment_configure_session(): bool
{
    if (
        !os_payment_is_https()
        || session_status() === PHP_SESSION_ACTIVE
    ) {
        return false;
    }

    $settings = [
        'session.use_only_cookies' => '1',
        'session.use_cookies' => '1',
        'session.use_strict_mode' => '1',
        'session.use_trans_sid' => '0',
        'session.cookie_secure' => '1',
        'session.cookie_httponly' => '1',
    ];

    foreach ($settings as $name => $value) {
        if (ini_set($name, $value) === false) {
            return false;
        }
    }

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    return true;
}

/**
 * Regenerates the session identifier.
 */
function os_payment_regenerate_session(): bool
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return false;
    }

    return session_regenerate_id(true);
}

/**
 * Validates a server-side user identifier.
 */
function os_payment_is_valid_user_id(
    string $userId
): bool {
    if (
        $userId === ''
        || strlen($userId) > OS_PAYMENT_MAX_IDENTIFIER_LENGTH
    ) {
        return false;
    }

    return preg_match(
        '/\A[A-Za-z0-9._:@-]+\z/D',
        $userId
    ) === 1;
}

/**
 * Validates a privilege identifier.
 */
function os_payment_is_valid_privilege(
    string $privilege
): bool {
    return $privilege !== ''
        && strlen($privilege)
            <= OS_PAYMENT_MAX_PRIVILEGE_LENGTH
        && preg_match(
            '/\A[a-z0-9][a-z0-9._:-]*\z/D',
            $privilege
        ) === 1;
}

/**
 * Establishes authenticated server-side session state.
 *
 * Privileges must come exclusively from trusted server-side sources.
 *
 * @param list<string> $privileges
 */
function os_payment_establish_authentication(
    string $userId,
    array $privileges = []
): bool {
    if (
        session_status() !== PHP_SESSION_ACTIVE
        || !os_payment_is_valid_user_id($userId)
    ) {
        return false;
    }

    $normalizedPrivileges = [];

    foreach ($privileges as $privilege) {
        if (
            !is_string($privilege)
            || !os_payment_is_valid_privilege(
                $privilege
            )
        ) {
            continue;
        }

        $normalizedPrivileges[
            $privilege
        ] = true;
    }

    if (!os_payment_regenerate_session()) {
        return false;
    }

    $now = time();

    $_SESSION[
        OS_PAYMENT_SESSION_AUTH_KEY
    ] = [
        'user_id' => $userId,
        'authenticated_at' => $now,
        'last_activity' => $now,
        'privileges' => array_keys(
            $normalizedPrivileges
        ),
    ];

    unset(
        $_SESSION[
            OS_PAYMENT_SESSION_CSRF_KEY
        ]
    );

    return true;
}

/**
 * Validates authenticated session lifetime.
 */
function os_payment_validate_authenticated_session(): bool
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return false;
    }

    $authentication = $_SESSION[
        OS_PAYMENT_SESSION_AUTH_KEY
    ] ?? null;

    if (!is_array($authentication)) {
        return false;
    }

    $userId = $authentication['user_id']
        ?? null;

    $authenticatedAt = $authentication[
        'authenticated_at'
    ] ?? null;

    $lastActivity = $authentication[
        'last_activity'
    ] ?? null;

    if (
        !is_string($userId)
        || !os_payment_is_valid_user_id($userId)
        || !is_int($authenticatedAt)
        || !is_int($lastActivity)
    ) {
        os_payment_clear_authentication();

        return false;
    }

    $now = time();

    if (
        $authenticatedAt > $now
        || $lastActivity > $now
        || (
            $now - $authenticatedAt
        ) > OS_PAYMENT_SESSION_ABSOLUTE_TIMEOUT
        || (
            $now - $lastActivity
        ) > OS_PAYMENT_SESSION_IDLE_TIMEOUT
    ) {
        os_payment_clear_authentication();

        return false;
    }

    $_SESSION[
        OS_PAYMENT_SESSION_AUTH_KEY
    ]['last_activity'] = $now;

    return true;
}

/**
 * Determines whether the current session is authenticated.
 */
function os_payment_is_authenticated(): bool
{
    return os_payment_validate_authenticated_session();
}

/**
 * Performs least-privilege authorization.
 *
 * Authorization is deny-by-default.
 */
function os_payment_authorize(
    string $requiredPrivilege
): bool {
    if (
        !os_payment_is_valid_privilege(
            $requiredPrivilege
        )
        || !os_payment_is_authenticated()
    ) {
        return false;
    }

    $authentication = $_SESSION[
        OS_PAYMENT_SESSION_AUTH_KEY
    ] ?? null;

    if (
        !is_array($authentication)
        || !isset($authentication['privileges'])
        || !is_array(
            $authentication['privileges']
        )
    ) {
        return false;
    }

    foreach (
        $authentication['privileges']
        as $grantedPrivilege
    ) {
        if (
            !is_string($grantedPrivilege)
            || !os_payment_is_valid_privilege(
                $grantedPrivilege
            )
        ) {
            continue;
        }

        if (
            hash_equals(
                $requiredPrivilege,
                $grantedPrivilege
            )
        ) {
            return true;
        }
    }

    return false;
}

/**
 * Removes authenticated state.
 */
function os_payment_clear_authentication(): bool
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return false;
    }

    unset(
        $_SESSION[
            OS_PAYMENT_SESSION_AUTH_KEY
        ],
        $_SESSION[
            OS_PAYMENT_SESSION_CSRF_KEY
        ]
    );

    return session_regenerate_id(true);
}

/**
 * Validates a CSRF token format.
 */
function os_payment_is_valid_csrf_token(
    string $token
): bool {
    return strlen($token)
            === OS_PAYMENT_HASH_HEX_LENGTH
        && preg_match(
            '/\A[0-9a-f]{64}\z/D',
            $token
        ) === 1;
}

/**
 * Returns or creates a CSRF token.
 */
function os_payment_csrf_token(): ?string
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return null;
    }

    $existing = $_SESSION[
        OS_PAYMENT_SESSION_CSRF_KEY
    ] ?? null;

    if (
        is_string($existing)
        && os_payment_is_valid_csrf_token(
            $existing
        )
    ) {
        return $existing;
    }

    try {
        $token = bin2hex(
            random_bytes(OS_PAYMENT_CSRF_BYTES)
        );
    } catch (Throwable) {
        return null;
    }

    $_SESSION[
        OS_PAYMENT_SESSION_CSRF_KEY
    ] = $token;

    return $token;
}

/**
 * Rotates a CSRF token.
 */
function os_payment_rotate_csrf_token(): ?string
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return null;
    }

    unset(
        $_SESSION[
            OS_PAYMENT_SESSION_CSRF_KEY
        ]
    );

    return os_payment_csrf_token();
}

/**
 * Validates a submitted CSRF token using constant-time comparison.
 */
function os_payment_verify_csrf(
    mixed $provided
): bool {
    if (
        session_status() !== PHP_SESSION_ACTIVE
        || !is_string($provided)
    ) {
        return false;
    }

    $stored = $_SESSION[
        OS_PAYMENT_SESSION_CSRF_KEY
    ] ?? null;

    if (
        !is_string($stored)
        || !os_payment_is_valid_csrf_token(
            $stored
        )
        || !os_payment_is_valid_csrf_token(
            $provided
        )
    ) {
        return false;
    }

    return hash_equals(
        $stored,
        $provided
    );
}

/**
 * Checks whether a request method is appropriate for a state-changing
 * operation.
 */
function os_payment_is_state_changing_method(): bool
{
    $method = $_SERVER[
        'REQUEST_METHOD'
    ] ?? '';

    if (!is_string($method)) {
        return false;
    }

    return in_array(
        strtoupper($method),
        [
            'POST',
            'PUT',
            'PATCH',
            'DELETE',
        ],
        true
    );
}

/**
 * Validates all requirements for a privileged state-changing operation.
 */
function os_payment_validate_state_change(
    mixed $csrfToken,
    string $requiredPrivilege
): bool {
    if (
        !os_payment_is_https()
        || !os_payment_is_state_changing_method()
        || !os_payment_is_authenticated()
        || !os_payment_authorize(
            $requiredPrivilege
        )
    ) {
        return false;
    }

    return os_payment_verify_csrf(
        $csrfToken
    );
}

/**
 * Sends restrictive HTTP security headers.
 */
function os_payment_send_security_headers(): void
{
    if (headers_sent()) {
        return;
    }

    $headers = [
        'Cache-Control: no-store, no-cache, must-revalidate, max-age=0',
        'Pragma: no-cache',
        'Expires: 0',
        'X-Content-Type-Options: nosniff',
        'X-Frame-Options: DENY',
        'Referrer-Policy: no-referrer',
        'Cross-Origin-Opener-Policy: same-origin',
        'Cross-Origin-Resource-Policy: same-origin',
        'Permissions-Policy: '
            . 'camera=(), '
            . 'microphone=(), '
            . 'geolocation=(), '
            . 'payment=(), '
            . 'usb=()',
        "Content-Security-Policy: "
            . "default-src 'self'; "
            . "base-uri 'self'; "
            . "object-src 'none'; "
            . "frame-ancestors 'none'; "
            . "form-action 'self'; "
            . "script-src 'self'; "
            . "style-src 'self'; "
            . "img-src 'self' data:; "
            . "font-src 'self'; "
            . "connect-src 'self'; "
            . "upgrade-insecure-requests",
    ];

    foreach ($headers as $headerValue) {
        header(
            $headerValue,
            true
        );
    }

    if (os_payment_is_https()) {
        header(
            'Strict-Transport-Security: '
            . 'max-age=31536000; '
            . 'includeSubDomains',
            true
        );
    }
}

/**
 * Redacts sensitive information before logging.
 */
function os_payment_redact(
    mixed $value
): string {
    unset($value);

    return '[REDACTED]';
}

/**
 * Removes obvious control characters from non-secret values intended
 * exclusively for protected server-side logs.
 */
function os_payment_sanitize_log_value(
    string $value,
    int $maxLength = 200
): string {
    $value = preg_replace(
        '/[\x00-\x1F\x7F]/',
        '',
        $value
    ) ?? '';

    if ($maxLength < 1) {
        return '';
    }

    if (strlen($value) > $maxLength) {
        return substr(
            $value,
            0,
            $maxLength
        );
    }

    return $value;
}

/**
 * Returns a generic public error response.
 */
function os_payment_public_error(): string
{
    return 'Unable to process the request.';
}

/**
 * Explicitly disables the legacy plaintext-cookie mechanism.
 */
function os_payment_get_legacy_cookie(): int
{
    return 0;
}

