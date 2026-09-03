<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

/**
 * Encodes text for safe use in cookie names.
 *
 * @param string $text Text to encode.
 * @return string Encoded text.
 */
function os_payment_encode(string $text): string
{
    $normalizedText = str_replace([' ', '.'], '_', trim($text));

    return rawurlencode($normalizedText);
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
    $version = trim($version);

    if ($version === '' || $amount < 0) {
        return false;
    }

    $cookieName = os_payment_encode("os_payment_{$version}");

    if ($cookieName === '') {
        return false;
    }

    return setcookie(
        $cookieName,
        (string) $amount,
        [
            'expires'  => time() + 31536000,
            'path'     => '/',
            'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
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
    $version = trim($version);

    if ($version === '') {
        return os_payment_get_legacy_cookie();
    }

    $cookieNames = [
        os_payment_encode("os_payment_{$version}"),
        os_payment_encode("has_paid_Loki_{$version}"),
    ];

    foreach ($cookieNames as $cookieName) {
        if (!isset($_COOKIE[$cookieName])) {
            continue;
        }

        $amount = os_payment_parse_amount($_COOKIE[$cookieName]);

        if ($amount > 0) {
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
        !isset($config['release_title'], $config['release_version'])
        || !is_string($config['release_title'])
        || !is_string($config['release_version'])
    ) {
        return 0;
    }

    $releaseTitle = trim($config['release_title']);
    $releaseVersion = trim($config['release_version']);

    if ($releaseTitle === '' || $releaseVersion === '') {
        return 0;
    }

    $cookieName = os_payment_encode(
        "has_paid_{$releaseTitle}_{$releaseVersion}"
    );

    if (!isset($_COOKIE[$cookieName])) {
        return 0;
    }

    return os_payment_parse_amount($_COOKIE[$cookieName]);
}

/**
 * Safely parses a payment amount received from a cookie.
 *
 * @param mixed $value Cookie value.
 * @return int Valid non-negative amount, or 0 for invalid values.
 */
function os_payment_parse_amount(mixed $value): int
{
    if (is_int($value)) {
        return $value >= 0 ? $value : 0;
    }

    if (!is_string($value)) {
        return 0;
    }

    $value = trim($value);

    if ($value === '' || !ctype_digit($value)) {
        return 0;
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

    return $amount === false ? 0 : $amount;
}
