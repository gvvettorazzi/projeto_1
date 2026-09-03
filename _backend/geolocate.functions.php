<?php

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/log-echo.php';

use GeoIp2\Database\Reader;

/**
 * Path to the GeoIP database.
 */
const GEOIP_DATABASE_PATH = __DIR__ . '/GeoLite2-City.mmdb';

/**
 * Returns a shared GeoIP reader instance.
 *
 * Reusing the reader avoids reopening the GeoIP database
 * multiple times during the same request.
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

    if (!is_readable(GEOIP_DATABASE_PATH)) {
        throw new RuntimeException(
            'GeoIP database not found or not readable: ' . GEOIP_DATABASE_PATH
        );
    }

    $reader = new Reader(GEOIP_DATABASE_PATH);

    return $reader;
}

/**
 * Handles GeoIP errors consistently.
 *
 * @param Throwable $exception
 * @param bool      $debug
 */
function handleGeoIpError($exception, $debug = false)
{
    $message = $exception->getMessage();

    if ($debug) {
        echo $message . PHP_EOL;

        return;
    }

    error_log($message);
}

/**
 * Looks up an IP address using the GeoIP database.
 *
 * Returns null when the lookup cannot be completed.
 *
 * @param string $hostname
 * @param bool   $debug
 *
 * @return mixed|null
 */
function getGeoIpRecord($hostname, $debug = false)
{
    try {
        return getGeoIpReader()->city($hostname);
    } catch (Throwable $exception) {
        handleGeoIpError($exception, $debug);

        return null;
    }
}

/**
 * Determines the preferred download region for an IP address.
 *
 * A string means that a single region should be used.
 * An array means that traffic may be balanced between two regions.
 *
 * @param string $hostname
 * @param bool   $debug
 *
 * @return string|array
 */
function getDownloadRegion($hostname, $debug = false)
{
    $record = getGeoIpRecord($hostname, $debug);

    $continent = $record ? $record->continent->code : null;
    $country = $record ? $record->country->isoCode : null;
    $longitude = $record ? $record->location->longitude : null;

    if ($debug) {
        echo 'Continent: "' . ($continent ?? '') . '"' . PHP_EOL;
        echo 'Country: "' . ($country ?? '') . '"' . PHP_EOL;
        echo 'Longitude: "' . ($longitude ?? '') . '"' . PHP_EOL;
    }

    switch ($continent) {
        case 'NA':
            return getNorthAmericaRegion($country, $longitude);

        case 'EU':
            return getEuropeRegion($country);

        case 'SA':
            return ['nyc3', 'sfo1'];

        case 'AF':
            return ['fra1', 'ams3'];

        case 'AS':
        case 'OC':
        case 'AN':
            return 'sgp1';

        default:
            // Graceful fallback when GeoIP is unavailable
            // or the continent cannot be determined.
            return ['nyc3', 'ams3'];
    }
}

/**
 * Determines the download region for North America.
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

    if (
        in_array($country, $westCoastCountries, true) ||
        ($longitude !== null && $longitude < -100)
    ) {
        return 'sfo1';
    }

    if (
        in_array($country, $eastCoastCountries, true) ||
        ($longitude !== null && $longitude >= -100)
    ) {
        return 'nyc3';
    }

    return ['nyc3', 'sfo1'];
}

/**
 * Determines the download region for Europe.
 *
 * @param string|null $country
 *
 * @return string|array
 */
function getEuropeRegion($country)
{
    static $amsCountries = [
        // British Isles / North Atlantic
        'GB',
        'IM',
        'IE',
        'FO',
        'IS',
        'GG',
        'JE',
        'GI',

        // Northern Europe
        'NL',
        'SX',
        'DK',
        'NO',
        'SE',
        'FI',
        'SJ',
    ];

    if (in_array($country, $amsCountries, true)) {
        return 'ams3';
    }

    return ['ams3', 'fra1'];
}

/**
 * Generates a deterministic value (0 or 1) from an IP address.
 *
 * Used when balancing traffic between the two regions returned
 * by getDownloadRegion().
 *
 * @param string $hostname
 * @param bool   $debug
 *
 * @return int
 */
function getIPHash($hostname, $debug = false)
{
    $hash = array_sum(str_split($hostname));

    if ($debug) {
        echo 'Hash: "' . $hash . '"' . PHP_EOL;
    }

    $remainder = $hash % 10;

    if ($debug) {
        echo 'Remainder: "' . $remainder . '"' . PHP_EOL;
    }

    return $remainder > 5 ? 0 : 1;
}

/**
 * Returns geographical information for an IP address.
 *
 * All fields are returned as false when the GeoIP lookup fails,
 * maintaining compatibility with the previous implementation.
 *
 * @param string $hostname
 * @param bool   $debug
 *
 * @return array
 */
function getCurrentLocation($hostname, $debug = false)
{
    if ($debug) {
        echo $hostname . PHP_EOL;
    }

    $record = getGeoIpRecord($hostname, $debug);

    if ($record === null) {
        return emptyLocation();
    }

    return [
        'city' => $record->city->name,
        'state' => $record->mostSpecificSubdivision->name,
        'stateCode' => $record->mostSpecificSubdivision->isoCode,
        'country' => $record->country->name,
        'countryCode' => $record->country->isoCode,
        'postcode' => $record->postal->code,
        'continent' => $record->continent->code,
    ];
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

