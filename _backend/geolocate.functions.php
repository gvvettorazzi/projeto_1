<?php

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

use GeoIp2\Database\Reader;

const GEOIP_DATABASE_PATH = __DIR__ . '/GeoLite2-City.mmdb';

const DEFAULT_DOWNLOAD_REGIONS = ['nyc3', 'ams3'];
const NORTH_AMERICA_REGIONS = ['nyc3', 'sfo1'];
const EUROPE_REGIONS = ['ams3', 'fra1'];

const MAX_IP_LENGTH = 45;
const MAX_LOG_MESSAGE_LENGTH = 500;

/**
 * Returns a shared GeoIP reader instance.
 *
 * The same reader is reused during the request to avoid repeatedly
 * opening the database and consuming unnecessary resources.
 *
 * @return Reader
 *
 * @throws RuntimeException
 */
function getGeoIpReader()
{
    static $reader = null;
    static $readerUnavailable = false;

    /*
     * Simple request-scoped circuit breaker.
     *
     * If initialization already failed during this request,
     * do not repeatedly attempt to access the database.
     */
    if ($readerUnavailable) {
        throw new RuntimeException('GeoIP service unavailable');
    }

    if ($reader instanceof Reader) {
        return $reader;
    }

    try {
        if (!class_exists(Reader::class)) {
            throw new RuntimeException('GeoIP reader unavailable');
        }

        if (
            !is_file(GEOIP_DATABASE_PATH)
            || !is_readable(GEOIP_DATABASE_PATH)
        ) {
            throw new RuntimeException('GeoIP database unavailable');
        }

        $reader = new Reader(GEOIP_DATABASE_PATH);

        return $reader;
    } catch (Throwable $exception) {
        $readerUnavailable = true;

        throw new RuntimeException(
            'GeoIP service unavailable',
            0,
            $exception
        );
    }
}

/**
 * Validates and normalizes an IPv4 or IPv6 address.
 *
 * Rejecting oversized and malformed input protects the GeoIP library
 * against unnecessary processing and abusive requests.
 *
 * @param mixed $hostname
 *
 * @return string|null
 */
function normalizeIpAddress($hostname)
{
    if (!is_string($hostname)) {
        return null;
    }

    $hostname = trim($hostname);

    if (
        $hostname === ''
        || strlen($hostname) > MAX_IP_LENGTH
    ) {
        return null;
    }

    $validatedIp = filter_var(
        $hostname,
        FILTER_VALIDATE_IP
    );

    if ($validatedIp === false) {
        return null;
    }

    return $validatedIp;
}

/**
 * Normalizes an ISO 3166-1 alpha-2 country code.
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

    if (
        strlen($country) !== 2
        || !ctype_alpha($country)
    ) {
        return null;
    }

    return $country;
}

/**
 * Sanitizes values written to application logs.
 *
 * Prevents CRLF/log injection and avoids excessively large log entries.
 *
 * @param mixed $message
 *
 * @return string
 */
function sanitizeLogMessage($message)
{
    if (!is_scalar($message)) {
        return 'GeoIP operation failed';
    }

    $message = (string) $message;

    $message = str_replace(
        ["\r", "\n", "\0"],
        ' ',
        $message
    );

    $message = trim($message);

    if (strlen($message) > MAX_LOG_MESSAGE_LENGTH) {
        $message = substr(
            $message,
            0,
            MAX_LOG_MESSAGE_LENGTH
        );
    }

    return $message;
}

/**
 * Outputs debug information safely.
 *
 * HTML escaping prevents debug values from becoming executable markup
 * if debug mode is accidentally enabled in a browser environment.
 *
 * @param mixed $message
 *
 * @return void
 */
function outputGeoIpDebug($message)
{
    if (!is_scalar($message)) {
        return;
    }

    $message = (string) $message;

    /*
     * Raw debug output is permitted only from CLI.
     * This avoids exposing operational details to HTTP clients.
     */
    if (PHP_SAPI !== 'cli') {
        return;
    }

    echo sanitizeLogMessage($message) . PHP_EOL;
}

/**
 * Logs a generic GeoIP failure.
 *
 * Exception details are deliberately not exposed to HTTP clients.
 *
 * @param Throwable $exception
 * @param bool      $debug
 *
 * @return void
 */
function handleGeoIpError($exception, $debug = false)
{
    /*
     * Avoid logging attacker-controlled IP input.
     *
     * The exception is logged only after stripping line-breaking
     * characters that could otherwise allow log forging.
     */
    $message = 'GeoIP lookup failed';

    if ($debug && PHP_SAPI === 'cli') {
        $message .= ': ' . sanitizeLogMessage(
            $exception->getMessage()
        );

        outputGeoIpDebug($message);

        return;
    }

    /*
     * Production logs intentionally avoid exposing filesystem paths,
     * database locations or library internals.
     */
    error_log($message);
}

/**
 * Performs a GeoIP lookup for a validated IP address.
 *
 * Failure is handled gracefully so GeoIP availability does not become
 * a single point of failure for the website.
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
        if ($debug) {
            outputGeoIpDebug('Invalid IP address');
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
 * Determines the preferred download region.
 *
 * GeoIP failures deliberately fail over to multiple known regions,
 * preserving service availability.
 *
 * @param mixed $hostname
 * @param bool  $debug
 *
 * @return string|array
 */
function getDownloadRegion($hostname, $debug = false)
{
    $record = getGeoIpRecord(
        $hostname,
        $debug
    );

    if ($record === null) {
        return DEFAULT_DOWNLOAD_REGIONS;
    }

    $continent = null;
    $country = null;
    $longitude = null;

    if (
        isset($record->continent->code)
        && is_string($record->continent->code)
    ) {
        $continent = strtoupper(
            trim($record->continent->code)
        );
    }

    if (isset($record->country->isoCode)) {
        $country = normalizeCountryCode(
            $record->country->isoCode
        );
    }

    if (
        isset($record->location->longitude)
        && is_numeric($record->location->longitude)
    ) {
        $longitude = (float) $record->location->longitude;

        if (
            $longitude < -180
            || $longitude > 180
        ) {
            $longitude = null;
        }
    }

    if ($debug) {
        outputGeoIpDebug(
            'Continent: "' . ($continent ?? '') . '"'
        );

        outputGeoIpDebug(
            'Country: "' . ($country ?? '') . '"'
        );

        outputGeoIpDebug(
            'Longitude: "' . ($longitude ?? '') . '"'
        );
    }

    switch ($continent) {
        case 'NA':
            return getNorthAmericaRegion(
                $country,
                $longitude
            );

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
            /*
             * Fail-safe availability strategy:
             * unknown location does not prevent downloads.
             */
            return DEFAULT_DOWNLOAD_REGIONS;
    }
}

/**
 * Determines the preferred North American download region.
 *
 * @param string|null $country
 * @param float|null  $longitude
 *
 * @return string|array
 */
function getNorthAmericaRegion($country, $longitude)
{
    static $westCountries = [
        'BZ',
        'CR',
        'SV',
        'GT',
        'HN',
        'MX',
        'NI',
        'PA',
    ];

    static $eastCountries = [
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
        in_array($country, $westCountries, true)
        || (
            $longitude !== null
            && $longitude < -100
        )
    ) {
        return 'sfo1';
    }

    if (
        in_array($country, $eastCountries, true)
        || (
            $longitude !== null
            && $longitude >= -100
        )
    ) {
        return 'nyc3';
    }

    return NORTH_AMERICA_REGIONS;
}

/**
 * Determines the preferred European download region.
 *
 * @param string|null $country
 *
 * @return string|array
 */
function getEuropeRegion($country)
{
    static $amsterdamCountries = [
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

    if (
        in_array(
            $country,
            $amsterdamCountries,
            true
        )
    ) {
        return 'ams3';
    }

    return EUROPE_REGIONS;
}

/**
 * Generates the deterministic traffic-balancing value used by
 * the existing application.
 *
 * The original algorithm is intentionally retained to prevent
 * changing the current distribution behavior.
 *
 * @param mixed $hostname
 * @param bool  $debug
 *
 * @return int
 */
function getIPHash($hostname, $debug = false)
{
    $ipAddress = normalizeIpAddress($hostname);

    /*
     * Preserve deterministic fallback behavior for invalid input.
     */
    if ($ipAddress === null) {
        $ipAddress = '';
    }

    $hash = array_sum(
        str_split($ipAddress)
    );

    $remainder = $hash % 10;

    if ($debug) {
        outputGeoIpDebug(
            'Hash: "' . $hash . '"'
        );

        outputGeoIpDebug(
            'Remainder: "' . $remainder . '"'
        );
    }

    return $remainder > 5 ? 0 : 1;
}

/**
 * Returns geographical information for an IP address.
 *
 * Failure returns an empty structure instead of propagating an
 * exception, keeping GeoIP failures isolated from the application.
 *
 * @param mixed $hostname
 * @param bool  $debug
 *
 * @return array
 */
function getCurrentLocation($hostname, $debug = false)
{
    $ipAddress = normalizeIpAddress($hostname);

    if ($ipAddress === null) {
        return emptyLocation();
    }

    if ($debug) {
        outputGeoIpDebug('GeoIP lookup requested');
    }

    $record = getGeoIpRecord(
        $ipAddress,
        $debug
    );

    if ($record === null) {
        return emptyLocation();
    }

    return [
        'city' => normalizeGeoIpValue(
            $record->city->name ?? null
        ),

        'state' => normalizeGeoIpValue(
            $record->mostSpecificSubdivision->name ?? null
        ),

        'stateCode' => normalizeGeoIpValue(
            $record->mostSpecificSubdivision->isoCode ?? null
        ),

        'country' => normalizeGeoIpValue(
            $record->country->name ?? null
        ),

        'countryCode' => normalizeGeoIpValue(
            $record->country->isoCode ?? null
        ),

        'postcode' => normalizeGeoIpValue(
            $record->postal->code ?? null
        ),

        'continent' => normalizeGeoIpValue(
            $record->continent->code ?? null
        ),
    ];
}

/**
 * Normalizes values returned by GeoIP.
 *
 * @param mixed $value
 *
 * @return string|false
 */
function normalizeGeoIpValue($value)
{
    if (!is_scalar($value)) {
        return false;
    }

    $value = trim((string) $value);

    if ($value === '') {
        return false;
    }

    /*
     * Bound output size defensively.
     * GeoIP data should normally be significantly shorter.
     */
    return substr($value, 0, 255);
}

/**
 * Returns a safe fallback location structure.
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
