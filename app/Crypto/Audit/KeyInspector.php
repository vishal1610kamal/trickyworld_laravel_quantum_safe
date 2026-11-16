<?php

namespace App\Crypto\Audit;

/**
 * Names the algorithm behind a PEM public key or certificate, such as Passport's oauth-public.key.
 */
final class KeyInspector
{
    /**
     * DER-encoded OID prefixes from NIST's registry: 2.16.840.1.101.3.4.3.x (signatures) and .4.x (KEMs).
     */
    private const PQ_OIDS = [
        "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x11" => 'ML-DSA-44',
        "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x12" => 'ML-DSA-65',
        "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x13" => 'ML-DSA-87',
        "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x04\x01" => 'ML-KEM-512',
        "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x04\x02" => 'ML-KEM-768',
        "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x04\x03" => 'ML-KEM-1024',
    ];

    /**
     * @return array{algorithm: string, bits: int|null, quantum_safe: bool}|null null when the PEM can't be read
     */
    public static function inspect(string $pem): ?array
    {
        // Only for a bare public key: in a certificate, the issuer's signature algorithm OID appears too.
        if (str_contains($pem, '-----BEGIN PUBLIC KEY-----')) {
            foreach (self::PQ_OIDS as $oid => $name) {
                if (str_contains(self::der($pem), $oid)) {
                    return ['algorithm' => $name, 'bits' => null, 'quantum_safe' => true];
                }
            }
        }

        $key = @openssl_pkey_get_public($pem);

        if ($key === false) {
            return null;
        }

        $details = openssl_pkey_get_details($key);

        $algorithm = match ($details['type']) {
            OPENSSL_KEYTYPE_RSA => 'RSA',
            OPENSSL_KEYTYPE_EC => 'EC '.($details['ec']['curve_name'] ?? ''),
            OPENSSL_KEYTYPE_DSA => 'DSA',
            OPENSSL_KEYTYPE_DH => 'DH',
            default => 'other',
        };

        return ['algorithm' => trim($algorithm), 'bits' => $details['bits'] ?? null, 'quantum_safe' => false];
    }

    private static function der(string $pem): string
    {
        $body = preg_replace('/-----[^-]+-----|\s+/', '', $pem);

        return base64_decode((string) $body, true) ?: '';
    }
}
