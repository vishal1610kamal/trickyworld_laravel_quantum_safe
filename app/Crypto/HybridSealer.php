<?php

namespace App\Crypto;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Encryption\Encrypter;
use ParagonIE\PQCrypto\Compat;
use ParagonIE\PQCrypto\XWing;
use RuntimeException;
use SensitiveParameter;

/**
 * Seals values to a public key so that only the holder of the secret key can read them.
 *
 * X-Wing (ML-KEM-768 combined with X25519) produces a fresh 32-byte secret for every value.
 * HKDF-SHA256 turns that secret into an AES-256 key, and Laravel's own Encrypter does the
 * encryption with AES-256-GCM. A sealed value stays confidential unless both ML-KEM-768 and
 * X25519 are broken, so it is safe against a future quantum computer (ML-KEM) and against a
 * flaw in the new algorithm or its PHP implementation (X25519).
 *
 * Format: "pq1:" . base64(1,120-byte X-Wing ciphertext) . ":" . Laravel encrypted payload.
 *
 * The X-Wing calls go through pqcrypto_compat's Compat class, which uses Paragon's ext-pqcrypto (Rust)
 * when it is loaded and its pure-PHP code otherwise.
 */
final class HybridSealer
{
    public const PREFIX = 'pq1:';

    private const KDF_INFO = 'trickyworld/hybrid-sealer/v1';

    public function __construct(
        private readonly string $publicKey,
        #[SensitiveParameter] private readonly ?string $secretKey = null,
    ) {
        if (strlen($publicKey) !== XWing::ENCAPSULATION_KEY_SIZE) {
            throw new RuntimeException('The X-Wing public key must be '.XWing::ENCAPSULATION_KEY_SIZE.' bytes.');
        }

        if ($secretKey !== null) {
            if (strlen($secretKey) !== XWing::SEED_SIZE) {
                throw new RuntimeException('The X-Wing secret key must be '.XWing::SEED_SIZE.' bytes.');
            }

            [, $derived] = Compat::xwing_seed_keypair($secretKey);

            if (! hash_equals($derived->bytes(), $publicKey)) {
                throw new RuntimeException('The secret key does not belong to the configured public key.');
            }
        }
    }

    /**
     * Create a new key pair.
     *
     * @return array{public: string, secret: string} raw bytes: 1,216 and 32
     */
    public static function generateKeys(): array
    {
        [$secret, $public] = Compat::xwing_keygen();

        return ['public' => $public->bytes(), 'secret' => $secret->bytes()];
    }

    /**
     * Build a sealer from config/pq.php: the public key in base64, the secret key in a file.
     */
    public static function fromConfig(array $config): self
    {
        $public = base64_decode((string) ($config['public_key'] ?? ''), true);

        if ($public === false || $public === '') {
            throw new RuntimeException('Set PQ_SEAL_PUBLIC_KEY (run "php artisan pq:keygen").');
        }

        $secret = null;
        $path = $config['secret_key_path'] ?? null;

        if ($path !== null && $path !== '') {
            if (! is_readable($path)) {
                throw new RuntimeException("The secret key file {$path} is missing or unreadable.");
            }

            $secret = base64_decode(trim((string) file_get_contents($path)), true);

            if ($secret === false) {
                throw new RuntimeException("The secret key file {$path} is not base64.");
            }
        }

        return new self($public, $secret);
    }

    public static function isSealed(mixed $value): bool
    {
        return is_string($value) && str_starts_with($value, self::PREFIX);
    }

    public function canOpen(): bool
    {
        return $this->secretKey !== null;
    }

    /**
     * Seal a value. The context (a table and column, for example) must be given again to open it,
     * so a sealed value copied into another column will not open there.
     */
    public function seal(#[SensitiveParameter] string $plaintext, string $context = ''): string
    {
        ['sharedKey' => $shared, 'ciphertext' => $kemCiphertext] = Compat::xwing_encaps($this->publicKey);

        $payload = $this->encrypter($shared, $context)->encryptString($plaintext);

        return self::PREFIX.base64_encode($kemCiphertext).':'.$payload;
    }

    /**
     * Open a sealed value.
     *
     * @throws DecryptException when the value was tampered with, sealed for another key or context, or is not sealed
     */
    public function open(string $sealed, string $context = ''): string
    {
        if ($this->secretKey === null) {
            throw new RuntimeException('This server holds only the public key: it can seal values but not open them.');
        }

        if (! self::isSealed($sealed)) {
            throw new DecryptException('The value is not sealed.');
        }

        $parts = explode(':', substr($sealed, strlen(self::PREFIX)), 2);
        $kemCiphertext = base64_decode($parts[0], true);

        if (count($parts) !== 2 || $kemCiphertext === false || strlen($kemCiphertext) !== XWing::CIPHERTEXT_SIZE) {
            throw new DecryptException('The sealed value is malformed.');
        }

        $shared = Compat::xwing_decaps($this->secretKey, $kemCiphertext);

        return $this->encrypter($shared, $context)->decryptString($parts[1]);
    }

    private function encrypter(#[SensitiveParameter] string $shared, string $context): Encrypter
    {
        // X-Wing's shared secret already depends on the ciphertext and the public key, so a changed
        // ciphertext gives a different key and AES-GCM rejects the payload. The context is ours.
        $key = hash_hkdf('sha256', $shared, 32, self::KDF_INFO."\0".$context);

        return new Encrypter($key, 'aes-256-gcm');
    }
}
