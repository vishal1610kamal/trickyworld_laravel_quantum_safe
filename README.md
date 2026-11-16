# Quantum-safe encryption in Laravel

A Laravel 13 app with two tools for the post-quantum move: a sealer that encrypts values to a public key with
X-Wing (ML-KEM-768 combined with X25519), and an Artisan command that lists what in your app a quantum computer
could break and what it could not.

This is the code from the TrickyWorld guide to
[quantum-safe encryption in Laravel](https://www.trickyworld.in/programming/laravel/quantum-safe-encryption-laravel/),
which explains why each piece exists.

## What it does

1. **`php artisan pq:audit`** checks the parts that matter:
   - Laravel's own encryption (AES-256 is fine).
   - Which TLS library PHP really loads at run time, which can differ from the one it was built against.
   - With `--probe`, the key exchange your app's outbound HTTPS calls negotiate. The request goes through Laravel's
     HTTP client, so it shows what your payment and API calls get.
   - The algorithm of your Passport signing key.
   - Every RSA, elliptic-curve or JWT-signature call in your own code, read from PHP tokens so comments and look-alike
     method names are skipped.
2. **`App\Crypto\HybridSealer`** seals a value so that only the holder of a 32-byte secret key can read it. X-Wing
   produces a fresh shared secret per value, HKDF-SHA256 turns it into an AES-256 key, and Laravel's own `Encrypter`
   encrypts with AES-256-GCM. A sealed value stays secret unless both ML-KEM-768 and X25519 fall.
3. **`App\Casts\SealOnWrite`** is an Eloquent cast that seals an attribute when it is set and leaves it sealed when read.
   Web servers keep only the public key, so they can store a PAN or an ID number but never read it back. The worker
   that verifies it holds the secret key.

## Files

| File | Role |
|---|---|
| `app/Crypto/HybridSealer.php` | X-Wing + HKDF-SHA256 + Laravel's AES-256-GCM `Encrypter` |
| `app/Casts/SealOnWrite.php` | Write-only Eloquent cast (`CastsInboundAttributes`) |
| `app/Models/KycRecord.php` | Example model with a sealed `pan` column |
| `app/Console/Commands/PqKeygen.php` | `pq:keygen`: creates the key pair |
| `app/Console/Commands/PqAudit.php` | `pq:audit`: the readiness report |
| `app/Crypto/Audit/*` | Run-time TLS library check, trace probe, key inspector, code scanner |
| `config/pq.php` | Keys, trace URL, folders to scan |
| `tests/Fixtures/xwing-draft-11.json` | The three test vectors from the X-Wing Internet-Draft, version 11 |
| `tests/Fixtures/legacy/*` | RSA and JWT code for the scanner to find |

## Run it

Requires PHP 8.3+ (64-bit) and Composer.

```bash
composer install
cp .env.example .env
php artisan key:generate
php artisan migrate
php artisan pq:keygen          # writes storage/pq-seal.key (mode 0600) and prints PQ_SEAL_PUBLIC_KEY=...
```

Put the printed `PQ_SEAL_PUBLIC_KEY=` line in `.env`. Only on the machine that has to read sealed values, also set
`PQ_SEAL_SECRET_KEY_PATH` to the key file. Back the key file up offline: without it, sealed values are gone.

```php
$record = KycRecord::create(['name' => 'Asha', 'pan' => 'ABCDE1234F']);   // stored as pq1:...

// On the back-office machine, which holds the secret key:
$pan = app(HybridSealer::class)->open($record->pan, SealOnWrite::context($record, 'pan'));
```

## The audit

```bash
php artisan pq:audit                    # offline checks and the code scan
php artisan pq:audit --probe            # plus one HTTPS request to https://www.cloudflare.com/cdn-cgi/trace
php artisan pq:audit --json --strict    # for CI: exit code 1 if anything is left to do
```

Output on a Laravel 13.42 app with Passport 13.11, PHP 8.3.36 and Ubuntu 22.04's OpenSSL 3.0.2, scanning the fixtures:

```
[ok]    Laravel encryption    AES-256-CBC with a 32-byte key: symmetric, NIST's top post-quantum security category
[ok]    Password hashing      bcrypt: not public-key cryptography, so Shor's algorithm does not apply
[todo]  TLS library           ext/openssl loads OpenSSL 3.0.2 15 Mar 2022; ext/curl uses OpenSSL/3.0.2 (no ML-KEM: OpenSSL 3.5 or later needed)
[todo]  Outbound TLS          TLSv1.3, kex=X25519: classical, so traffic recorded today could be decrypted later
[todo]  Passport signing key  RSA-4096 (storage/oauth-public.key): tokens become forgeable once a quantum computer exists; keep them short-lived and rotate the key
[todo]  Public-key code       5 place(s) in app, tests/Fixtures/legacy, listed below
```

The `--probe` result depends on the TLS library PHP loads and on the server it talks to. With OpenSSL 3.5 or later,
PHP offers the hybrid `X25519MLKEM768` group by default, and servers that support it pick it.

## Tests

```bash
php artisan test
```

47 tests (86 assertions) pass on PHP 8.3.36 with PHPUnit 12.5.44. They cover the X-Wing test vectors, sealing and
opening, tampering, wrong keys and contexts, the cast, both commands, and the scanner. Nothing goes over the network:
the probe tests use `Http::fake()`.

## Limits

- **The post-quantum code is pure PHP and unaudited.** `paragonie/pqcrypto_compat` 0.3.4 says so in its README, and
  Paragon's announcement (7 April 2026) adds: "There will be bugs. Don't rush to deploy this into production yet."
  It matches all three X-Wing test vectors in this repo's tests, and X-Wing's X25519 half still protects you if the
  ML-KEM half has a bug. Where you can, install Paragon's `ext-pqcrypto` (Rust): the sealer uses it automatically, and Paragon
  describes it as faster and "higher assurance".
- **It is slow next to RSA.** On an Intel i5-10210U, sealing took 9.1 ms and opening 20.4 ms. RSA-2048
  `openssl_seal` took 0.6 ms each way. That is fine for a form submission or a queue job, but not for every request.
- **Sealed values are big.** A 10-byte PAN becomes 1,629 bytes, because the X-Wing ciphertext alone is 1,120 bytes.
  Use a `text` column.
- **X-Wing is still an Internet-Draft** (version 11, September 2026). ML-KEM-768 inside it is FIPS 203. The `pq1:`
  prefix leaves room for a format change.
- **PHP 8.6 adds `sodium_crypto_kem_*()`** (X-Wing from libsodium 1.0.22), due for release on 19 November 2026. It
  only exists when PHP is built against libsodium 1.0.22 or later, and Ubuntu 26.04 and Debian 13 ship 1.0.18. It
  was not tested here, so this repository does not use it yet.
- **The sealer does not replace TLS, Laravel's `Crypt` or password hashing.** Those are symmetric or hash-based and
  already fine. It replaces `openssl_seal()` and `openssl_public_encrypt()`.

## Licence

MIT.
