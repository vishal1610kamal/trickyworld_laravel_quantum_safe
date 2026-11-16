<?php

namespace Legacy;

/**
 * The pre-quantum way to store a PAN that only the back office can read: RSA key transport.
 * Kept as a scanner fixture. pq:audit must report the two calls below, but not this comment's
 * mention of openssl_public_encrypt() or the methods that share the names.
 */
class RsaKycVault
{
    public function __construct(private string $publicKeyPem, private ?string $privateKeyPem = null) {}

    public function seal(string $pan): string
    {
        openssl_seal($pan, $sealed, $keys, [$this->publicKeyPem], 'aes-256-cbc', $iv);

        return base64_encode($iv).':'.base64_encode($keys[0]).':'.base64_encode($sealed);
    }

    public function open(string $value): string
    {
        [$iv, $key, $sealed] = array_map('base64_decode', explode(':', $value));

        \openssl_open($sealed, $pan, $key, $this->privateKeyPem, 'aes-256-cbc', $iv);

        return $pan;
    }

    public function openssl_seal(): void
    {
        // A method with the same name is not the PHP function.
    }
}
