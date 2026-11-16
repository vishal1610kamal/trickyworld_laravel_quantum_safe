<?php

namespace App\Crypto\Audit;

use ReflectionExtension;

/**
 * Which TLS library this PHP process really uses.
 *
 * OPENSSL_VERSION_TEXT is the version of the headers PHP was compiled against. The library loaded at
 * run time can be newer (or older), and it is the run-time library that decides whether a TLS
 * handshake can offer ML-KEM. ext/curl may even use a different TLS library than ext/openssl.
 */
final class Runtime
{
    public static function opensslLibrary(): ?string
    {
        if (! extension_loaded('openssl')) {
            return null;
        }

        ob_start();
        (new ReflectionExtension('openssl'))->info();
        $info = strip_tags((string) ob_get_clean());

        return preg_match('/OpenSSL Library Version\s*(?:=>)?\s*([^\r\n]+)/', $info, $m) ? trim($m[1]) : null;
    }

    public static function opensslHeaders(): ?string
    {
        return defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : null;
    }

    public static function curlTls(): ?string
    {
        return function_exists('curl_version') ? (curl_version()['ssl_version'] ?? null) : null;
    }

    /**
     * Whether an OpenSSL version string belongs to a release with ML-KEM (3.5 or later).
     * Returns null for other TLS libraries (BoringSSL, AWS-LC, LibreSSL, GnuTLS...): probe those instead.
     */
    public static function hasMlKem(?string $version): ?bool
    {
        if ($version === null || ! preg_match('/OpenSSL[ \/](\d+)\.(\d+)\.(\d+)/i', $version, $m)) {
            return null;
        }

        return version_compare("{$m[1]}.{$m[2]}.{$m[3]}", '3.5.0', '>=');
    }
}
