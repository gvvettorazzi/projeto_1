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
    $text = str_replace([' ', '.'], '_', $text);

    return rawurlencode($text);
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

    /*
     * Keep the cookie lifetime limited to one year.
     * HttpOnly prevents JavaScript access.
     * Secure ensures the cookie is sent only over HTTPS.
     * SameSite=Lax reduces CSRF exposure.
     */
    $expires = time() + 31536000;

    return setcookie(
        $cookieName,
        (string) $amount,
        [
            'expires'  => $expires,
            'path'     => '/',
            'secure'   => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
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

    /*
     * Legacy cookie support.
     *
     * $config was previously referenced without being defined in this
     * function. Only use it when the expected configuration values exist.
     */
    if ($version === '') {
        global $config;

        if (
            isset($config['release_title'], $config['release_version'])
            && is_string($config['release_title'])
            && is_string($config['release_version'])
        ) {
            $legacyCookieName = os_payment_encode(
                'has_paid_' .
                $config['release_title'] .
                '_' .
                $config['release_version']
            );

            if (isset($_COOKIE[$legacyCookieName])) {
                return os_payment_parse_amount($_COOKIE[$legacyCookieName]);
            }
        }

        return 0;
    }

    $cookieName = os_payment_encode("os_payment_{$version}");
    $deprecatedCookieName = os_payment_encode("has_paid_Loki_{$version}");

    if (isset($_COOKIE[$cookieName])) {
        return os_payment_parse_amount($_COOKIE[$cookieName]);
    }

    if (isset($_COOKIE[$deprecatedCookieName])) {
        return os_payment_parse_amount($_COOKIE[$deprecatedCookieName]);
    }

    return 0;
}

/**
 * Safely parses a payment amount received from a cookie.
 *
 * @param mixed $value Cookie value.
 * @return int Valid non-negative amount, or 0 for invalid values.
 */
function os_payment_parse_amount(mixed $value): int
{
    if (!is_string($value) && !is_int($value)) {
        return 0;
    }

    $value = (string) $value;

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
?>
