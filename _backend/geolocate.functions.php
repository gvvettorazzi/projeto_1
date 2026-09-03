<?php

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

use GeoIp2\Database\Reader;

const GEOIP_DATABASE_PATH = __DIR__ . '/GeoLite2-City.mmdb';

const DEFAULT_DOWNLOAD_REGIONS = ['nyc3', 'ams3'];
const NORTH_AMERICA_REGIONS = ['nyc3', 'sfo1'];
const EUROPE_REGIONS = ['ams3', 'fra1'];

/**
 * Returns a shared GeoIP reader instance.
 *
 * @return Reader
 *
 * @throws RuntimeException
 */
function getGeoIpReader()
{
    static $reader = null;

    if ($reader instanceof Reader) {
        return $reader;
    }

    if (!class_exists(Reader::class)) {
        throw new RuntimeException('Class GeoIp2\Database\Reader not found');
    }

    if (!is_file(GEOIP_DATABASE_PATH) || !is_readable(GEOIP_DATABASE_PATH)) {
        throw new RuntimeException('GeoIP database is unavailable');
    }

    $reader = new Reader(GEOIP_DATABASE_PATH);

    return $reader;
}

/**
 * Normalizes and validates an IP address.
 *
 * Supports both IPv4 and IPv6.
 *
 * @param mixed $hostname
 *
 * @return string|null
 */
function normalizeIpAddress($hostname)
{
    if (!is_string($hostname) && !is_numeric($hostname)) {
        return null;
    }

    $hostname = trim((string) $hostname);

    if ($hostname === '' || strlen($hostname) > 45) {
        return null;
    }

    $validatedIp = filter_var($hostname, FILTER_VALIDATE_IP);

    return $validatedIp !== false ? $validatedIp : null;
}

/**
 * Sanitizes a generic input value while preserving compatibility
 * with existing string-based operations.
 *
 * @param mixed $value
 *
 * @return string
 */
function sanitizeStringInput($value)
{
    if (!is_scalar($value)) {
        return '';
    }

    $value = trim((string) $value);

    return substr($value, 0, 255);
}

/**
 * Safely outputs debug information.
 *
 * @param string $message
 *
 * @return void
 */
function outputDebug($message)
{
    $message = (string) $message;

    if (PHP_SAPI === 'cli') {
        echo $message . PHP_EOL;

        return;
    }

    echo htmlspecialchars(
        $message,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    ) . PHP_EOL;
}

/**
 * Handles GeoIP errors consistently.
 *
 * @param Throwable $exception
 * @param bool      $debug
 *
 * @return void
 */
function handleGeoIpError($exception, $debug = false)
{
    $message = $exception instanceof Throwable
        ? $exception->getMessage()
        : 'Unknown GeoIP error';

    if ((bool) $debug) {
        outputDebug($message);

        return;
    }

    error_log('GeoIP error: ' . $message);
}

/**
 * Looks up an IP address using the GeoIP database.
 *
 * @param mixed $hostname
 * @param bool  $debug
 *
 * @return mixed|null
 */
function getGeoIpRecord($hostname, $debug = false)
{
    $ipAddress = normalizeIpAddress($hostname);

    if ($ipAddress === null) {
        if ((bool) $debug) {
            outputDebug('Invalid IP address');
        }

        return null;
    }

    try {
        return getGeoIpReader()->city($ipAddress);
    } catch (Throwable $exception) {
        handleGeoIpError($exception, $debug);

        return null;
    }
}

/**
 * Determines the preferred download region for an IP address.
 *
 * @param mixed $hostname
 * @param bool  $debug
 *
 * @return string|array
 */
function getDownloadRegion($hostname, $debug = false)
{
    $record = getGeoIpRecord($hostname, $debug);

    if ($record === null) {
        return DEFAULT_DOWNLOAD_REGIONS;
    }

    $continent = isset($record->continent->code)
        ? (string) $record->continent->code
        : null;

    $country = isset($record->country->isoCode)
        ? (string) $record->country->isoCode
        : null;

    $longitude = isset($record->location->longitude)
        && is_numeric($record->location->longitude)
        ? (float) $record->location->longitude
        : null;

    if ((bool) $debug) {
        outputDebug('Continent: "' . ($continent ?? '') . '"');
        outputDebug('Country: "' . ($country ?? '') . '"');
        outputDebug('Longitude: "' . ($longitude ?? '') . '"');
    }

    switch ($continent) {
        case 'NA':
            return getNorthAmericaRegion($country, $longitude);

        case 'EU':
            return getEuropeRegion($country);

        case 'SA':
            return NORTH_AMERICA_REGIONS;

        case 'AF':
            return EUROPE_REGIONS;

        case 'AS':
        case 'OC':
        case 'AN':
            return 'sgp1';

        default:
            return DEFAULT_DOWNLOAD_REGIONS;
    }
}

/**
 * Determines the preferred download region for North America.
 *
 * @param string|null $country
 * @param float|null  $longitude
 *
 * @return string|array
 */
function getNorthAmericaRegion($country, $longitude)
{
    static $westCoastCountries = [
        'BZ',
        'CR',
        'SV',
        'GT',
        'HN',
        'MX',
        'NI',
        'PA',
    ];

    static $eastCoastCountries = [
        'AG',
        'BS',
        'BB',
        'BM',
        'VG',
        'KY',
        'CU',
        'DM',
        'DO',
        'GL',
        'GD',
        'GP',
        'HT',
        'JM',
        'MQ',
        'MS',
        'CW',
        'AW',
        'SX',
        'BQ',
        'PR',
        'BL',
        'KN',
        'AI',
        'LC',
        'MF',
        'PM',
        'VC',
        'TT',
        'TC',
        'VI',
    ];

    $country = normalizeCountryCode($country);

    if (
        in_array($country, $westCoastCountries, true)
        || ($longitude !== null && $longitude < -100)
    ) {
        return 'sfo1';
    }

    if (
        in_array($country, $eastCoastCountries, true)
        || ($longitude !== null && $longitude >= -100)
    ) {
        return 'nyc3';
    }

    return NORTH_AMERICA_REGIONS;
}

/**
 * Determines the preferred download region for Europe.
 *
 * @param string|null $country
 *
 * @return string|array
 */
function getEuropeRegion($country)
{
    static $amsCountries = [
        'GB',
        'IM',
        'IE',
        'FO',
        'IS',
        'GG',
        'JE',
        'GI',
        'NL',
        'SX',
        'DK',
        'NO',
        'SE',
        'FI',
        'SJ',
    ];

    $country = normalizeCountryCode($country);

    if (in_array($country, $amsCountries, true)) {
        return 'ams3';
    }

    return EUROPE_REGIONS;
}

/**
 * Normalizes an ISO country code.
 *
 * @param mixed $country
 *
 * @return string|null
 */
function normalizeCountryCode($country)
{
    if (!is_string($country)) {
        return null;
    }

    $country = strtoupper(trim($country));

    if (!preg_match('/^[A-Z]{2}$/', $country)) {
        return null;
    }

    return $country;
}

/**
 * Generates a deterministic value (0 or 1) from an address.
 *
 * The original hashing behavior is intentionally preserved
 * for compatibility with the existing traffic distribution.
 *
 * @param mixed $hostname
 * @param bool  $debug
 *
 * @return int
 */
function getIPHash($hostname, $debug = false)
{
    $hostname = sanitizeStringInput($hostname);

    $hash = array_sum(str_split($hostname));

    if ((bool) $debug) {
        outputDebug('Hash: "' . $hash . '"');
    }

    $remainder = $hash % 10;

    if ((bool) $debug) {
        outputDebug('Remainder: "' . $remainder . '"');
    }

    return $remainder > 5 ? 0 : 1;
}

/**
 * Returns geographical information for an IP address.
 *
 * @param mixed $hostname
 * @param bool  $debug
 *
 * @return array
 */
function getCurrentLocation($hostname, $debug = false)
{
    $ipAddress = normalizeIpAddress($hostname);

    if ((bool) $debug) {
        outputDebug($ipAddress ?? 'Invalid IP address');
    }

    if ($ipAddress === null) {
        return emptyLocation();
    }

    $record = getGeoIpRecord($ipAddress, $debug);

    if ($record === null) {
        return emptyLocation();
    }

    return [
        'city' => getGeoIpValue($record->city->name ?? null),
        'state' => getGeoIpValue(
            $record->mostSpecificSubdivision->name ?? null
        ),
        'stateCode' => getGeoIpValue(
            $record->mostSpecificSubdivision->isoCode ?? null
        ),
        'country' => getGeoIpValue($record->country->name ?? null),
        'countryCode' => getGeoIpValue(
            $record->country->isoCode ?? null
        ),
        'postcode' => getGeoIpValue($record->postal->code ?? null),
        'continent' => getGeoIpValue(
            $record->continent->code ?? null
        ),
    ];
}

/**
 * Normalizes a value returned by the GeoIP database.
 *
 * @param mixed $value
 *
 * @return string|false
 */
function getGeoIpValue($value)
{
    if ($value === null || $value === '') {
        return false;
    }

    if (!is_scalar($value)) {
        return false;
    }

    return trim((string) $value);
}

/**
 * Returns an empty location structure.
 *
 * @return array
 */
function emptyLocation()
{
    return [
        'city' => false,
        'state' => false,
        'stateCode' => false,
        'country' => false,
        'countryCode' => false,
        'postcode' => false,
        'continent' => false,
    ];
}

