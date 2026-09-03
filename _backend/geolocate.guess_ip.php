<?php

declare(strict_types=1);

function getClientIp(): string|false
{
    $candidates = [
        $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null,
        $_SERVER['REMOTE_ADDR'] ?? null,
    ];

    foreach ($candidates as $candidate) {
        if (
            is_string($candidate) &&
            filter_var($candidate, FILTER_VALIDATE_IP) !== false
        ) {
            return $candidate;
        }
    }

    return false;
}

$ip = getClientIp();

/*
 * Developer override.
 *
 * Configure DEV_IP_OVERRIDE as an environment variable instead
 * of hardcoding an IP address in the source code.
 */
$overrideIp = getenv('DEV_IP_OVERRIDE');

if (
    ($ip === '127.0.0.1' || isset($_GET['ip_override'])) &&
    is_string($overrideIp) &&
    filter_var($overrideIp, FILTER_VALIDATE_IP) !== false
) {
    $ip = $overrideIp;
}
