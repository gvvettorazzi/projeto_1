<?php

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

/**
 * Encodes text for use in cookie names.
 *
 * @param string $text Text to encode.
 * @return string Encoded text.
 */
function os_payment_encode(string $text): string
{
    return urlencode(str_replace([' ', '.'], '_', $text));
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
    $cookieName = os_payment_encode("os_payment_{$version}");
    $expires = time() + (365 * 24 * 60 * 60);

    return setcookie(
        $cookieName,
        (string) $amount,
        $expires,
        '/',
        '',
        false,
        true
    );
}

/**
 * Returns the amount paid for a release version.
 *
 * @param string $version Release version.
 * @return int Amount paid, or 0 if no payment cookie exists.
 */
function os_payment_getcookie(string $version): int
{
    if ($version === '') {
        $legacyCookieName = os_payment_encode(
            'has_paid_' . $config['release_title'] . '_' . $config['release_version']
        );

        if (isset($_COOKIE[$legacyCookieName])) {
            return (int) $_COOKIE[$legacyCookieName];
        }
    }

    $cookieName = os_payment_encode("os_payment_{$version}");
    $deprecatedCookieName = os_payment_encode("has_paid_Loki_{$version}");

    if (isset($_COOKIE[$cookieName])) {
        return (int) $_COOKIE[$cookieName];
    }

    if (isset($_COOKIE[$deprecatedCookieName])) {
        return (int) $_COOKIE[$deprecatedCookieName];
    }

    return 0;
}
?>


