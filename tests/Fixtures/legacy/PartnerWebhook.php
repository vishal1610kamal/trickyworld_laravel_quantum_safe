<?php

namespace Legacy;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Signs outgoing webhooks and checks incoming ones with RSA. Scanner fixture.
 */
class PartnerWebhook
{
    public function sign(array $payload, string $privateKeyPem): string
    {
        return JWT::encode($payload, $privateKeyPem, 'RS256');
    }

    public function verify(string $body, string $signature, string $partnerKeyPem): bool
    {
        return openssl_verify($body, base64_decode($signature), $partnerKeyPem, OPENSSL_ALGO_SHA256) === 1;
    }

    public function decode(string $jwt, string $publicKeyPem): object
    {
        return JWT::decode($jwt, new Key($publicKeyPem, 'RS256'));
    }

    public function digest(string $body): string
    {
        // HMAC and hashes are not public-key cryptography: nothing to report here.
        return hash_hmac('sha256', $body, 'webhook-secret');
    }
}
