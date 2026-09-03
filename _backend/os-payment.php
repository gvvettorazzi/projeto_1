<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

/**
 * Maximum accepted length for a release version.
 */
const OS_PAYMENT_MAX_VERSION_LENGTH = 128;

/**
 * Cookie lifetime in seconds (one year).
 */
const OS_PAYMENT_COOKIE_LIFETIME = 31536000;

/**
 * Encodes text for safe use in a cookie name.
 *
 * Cookie names are derived from trusted application identifiers rather
 * than arbitrary user-controlled input. The length limit additionally
 * prevents unnecessarily large cookie names.
 *
 * @param string $text Text to encode.
 * @return string Encoded text.
 */
function os_payment_encode(string $text): string
{
    $text = trim($text);

    if ($text === '' || strlen($text) > OS_PAYMENT_MAX_VERSION_LENGTH) {
        return '';
    }

    $text = str_replace([' ', '.'], '_', $text);

    return rawurlencode($text);
}

/**
 * Validates and normalizes a release version.
 *
 * The version is restricted to characters commonly used in release
 * identifiers. This prevents control characters, separators and other
 * unexpected values from becoming part of a cookie name.
 *
 * @param string $version Release version.
 * @return string Normalized version, or an empty string if invalid.
 */
function os_payment_normalize_version(string $version): string
{
    $version = trim($version);

    if (
        $version === ''
        || strlen($version) > OS_PAYMENT_MAX_VERSION_LENGTH
        || preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/', $version) !== 1
    ) {
        return '';
    }

    return $version;
}

/**
 * Determines whether the current request is using HTTPS.
 *
 * Only the standard HTTPS server variable is considered. This avoids
 * trusting arbitrary proxy headers such as X-Forwarded-Proto.
 *
 * @return bool True when HTTPS is enabled.
 */
function os_payment_is_https(): bool
{
    return isset($_SERVER['HTTPS'])
        && strtolower((string) $_SERVER['HTTPS']) !== 'off'
        && (string) $_SERVER['HTTPS'] !== '';
}

/**
 * Sets the payment cookie for a release version.
 *
 * @param string $version Release version.
 * @param int $amount Amount paid for the release.
 * @return bool True if the cookie was successfully set.
 */
function os_payment_setcookie(string $version, int $amount): bool
{
    $version = os_payment_normalize_version($version);

    if ($version === '' || $amount < 0) {
        return false;
    }

    $cookieName = os_payment_encode("os_payment_{$version}");

    if ($cookieName === '') {
        return false;
    }

    /*
     * Payment state should never be accessible to JavaScript.
     * Secure is enabled whenever the application is actually using HTTPS.
     * SameSite=Lax provides protection against most cross-site requests.
     */
    return setcookie(
        $cookieName,
        (string) $amount,
        [
            'expires'  => time() + OS_PAYMENT_COOKIE_LIFETIME,
            'path'     => '/',
            'secure'   => os_payment_is_https(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]
    );
}

/**
 * Returns the amount paid for a release version.
 *
 * @param string $version Release version.
 * @return int Amount paid, or 0 if no valid payment cookie exists.
 */
function os_payment_getcookie(string $version): int
{
    $version = os_payment_normalize_version($version);

    if ($version === '') {
        return os_payment_get_legacy_cookie();
    }

    $cookieNames = [
        os_payment_encode("os_payment_{$version}"),
        os_payment_encode("has_paid_Loki_{$version}"),
    ];

    foreach ($cookieNames as $cookieName) {
        if ($cookieName === '' || !array_key_exists($cookieName, $_COOKIE)) {
            continue;
        }

        $amount = os_payment_parse_amount($_COOKIE[$cookieName]);

        if ($amount !== null) {
            return $amount;
        }
    }

    return 0;
}

/**
 * Retrieves the legacy payment cookie.
 *
 * @return int Amount paid, or 0 if no valid legacy cookie exists.
 */
function os_payment_get_legacy_cookie(): int
{
    global $config;

    if (
        !is_array($config ?? null)
        || !isset($config['release_title'], $config['release_version'])
        || !is_string($config['release_title'])
        || !is_string($config['release_version'])
    ) {
        return 0;
    }

    $releaseTitle = trim($config['release_title']);
    $releaseVersion = os_payment_normalize_version(
        $config['release_version']
    );

    if ($releaseTitle === '' || $releaseVersion === '') {
        return 0;
    }

    /*
     * The legacy title is not expected to be user-controlled. Nevertheless,
     * reject control characters and impose a length limit before using it
     * in a cookie name.
     */
    if (
        strlen($releaseTitle) > OS_PAYMENT_MAX_VERSION_LENGTH
        || preg_match('/[\x00-\x1F\x7F]/', $releaseTitle) === 1
    ) {
        return 0;
    }

    $cookieName = os_payment_encode(
        "has_paid_{$releaseTitle}_{$releaseVersion}"
    );

    if ($cookieName === '' || !array_key_exists($cookieName, $_COOKIE)) {
        return 0;
    }

    $amount = os_payment_parse_amount($_COOKIE[$cookieName]);

    return $amount ?? 0;
}

/**
 * Parses and validates a payment amount received from a cookie.
 *
 * A null return value means the cookie is invalid.
 * This distinction prevents an invalid cookie from being confused with
 * a legitimate payment amount of zero.
 *
 * @param mixed $value Cookie value.
 * @return int|null Valid non-negative amount, or null when invalid.
 */
function os_payment_parse_amount(mixed $value): ?int
{
    if (!is_string($value)) {
        return null;
    }

    /*
     * Cookies arrive as strings. Do not silently cast arbitrary values
     * because values such as "10abc" or floating-point representations
     * could otherwise be interpreted incorrectly.
     */
    if (
        $value === ''
        || strlen($value) > 19
        || preg_match('/\A(?:0|[1-9][0-9]*)\z/', $value) !== 1
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
