<?php

namespace App\Crypto\Audit;

use Illuminate\Support\Facades\Http;

/**
 * Asks a Cloudflare /cdn-cgi/trace endpoint which key exchange this PHP process negotiated.
 *
 * The request goes through Laravel's HTTP client, so it uses the same Guzzle handler and TLS library
 * as your app's calls to payment gateways, OAuth providers and other APIs.
 */
final class TlsProbe
{
    /**
     * @return array<string, string> the trace's key=value lines, e.g. ['tls' => 'TLSv1.3', 'kex' => 'X25519']
     */
    public static function run(string $url): array
    {
        return self::parse(Http::timeout(10)->get($url)->throw()->body());
    }

    /**
     * @return array<string, string>
     */
    public static function parse(string $body): array
    {
        $fields = [];

        foreach (preg_split('/\r?\n/', trim($body)) as $line) {
            if (str_contains($line, '=')) {
                [$key, $value] = explode('=', $line, 2);
                $fields[trim($key)] = trim($value);
            }
        }

        return $fields;
    }

    /**
     * X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 are the hybrid groups in use today.
     */
    public static function isPostQuantum(?string $kex): ?bool
    {
        if ($kex === null || $kex === '') {
            return null;
        }

        return (bool) preg_match('/MLKEM|KYBER/i', $kex);
    }
}
