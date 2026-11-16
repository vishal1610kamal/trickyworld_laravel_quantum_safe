<?php

namespace App\Crypto\Audit;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Finds the public-key cryptography in your own code: the part a quantum computer breaks.
 *
 * It reads PHP tokens, so comments, method calls and function definitions with the same names are
 * not reported. AES, HMAC, hashing and Laravel's Crypt facade are not listed: Shor's algorithm
 * does not apply to them.
 */
final class CodeScanner
{
    private const EXCHANGE = 'encryption or key exchange: data recorded today can be decrypted later';

    private const SIGNATURE = 'signature: can be forged once a quantum computer exists';

    private const KEYGEN = 'key generation: check what the key is used for';

    /** @var array<string, string> */
    private const FUNCTIONS = [
        'openssl_public_encrypt' => self::EXCHANGE,
        'openssl_private_decrypt' => self::EXCHANGE,
        'openssl_seal' => self::EXCHANGE,
        'openssl_open' => self::EXCHANGE,
        'openssl_pkey_derive' => self::EXCHANGE,
        'openssl_dh_compute_key' => self::EXCHANGE,
        'openssl_pkcs7_encrypt' => self::EXCHANGE,
        'openssl_pkcs7_decrypt' => self::EXCHANGE,
        'openssl_cms_encrypt' => self::EXCHANGE,
        'openssl_cms_decrypt' => self::EXCHANGE,
        'sodium_crypto_box' => self::EXCHANGE,
        'sodium_crypto_box_open' => self::EXCHANGE,
        'sodium_crypto_box_seal' => self::EXCHANGE,
        'sodium_crypto_box_seal_open' => self::EXCHANGE,
        'sodium_crypto_box_keypair' => self::EXCHANGE,
        'sodium_crypto_kx_keypair' => self::EXCHANGE,
        'sodium_crypto_kx_client_session_keys' => self::EXCHANGE,
        'sodium_crypto_kx_server_session_keys' => self::EXCHANGE,
        'sodium_crypto_scalarmult' => self::EXCHANGE,
        'openssl_sign' => self::SIGNATURE,
        'openssl_verify' => self::SIGNATURE,
        'openssl_private_encrypt' => self::SIGNATURE,
        'openssl_public_decrypt' => self::SIGNATURE,
        'openssl_pkcs7_sign' => self::SIGNATURE,
        'openssl_cms_sign' => self::SIGNATURE,
        'sodium_crypto_sign' => self::SIGNATURE,
        'sodium_crypto_sign_open' => self::SIGNATURE,
        'sodium_crypto_sign_detached' => self::SIGNATURE,
        'sodium_crypto_sign_verify_detached' => self::SIGNATURE,
        'sodium_crypto_sign_keypair' => self::SIGNATURE,
        'openssl_pkey_new' => self::KEYGEN,
    ];

    /** @var array<string, string> lower-case class prefixes */
    private const CLASSES = [
        'phpseclib3\crypt\rsa' => self::KEYGEN,
        'phpseclib3\crypt\ec' => self::KEYGEN,
        'phpseclib3\crypt\dh' => self::EXCHANGE,
        'phpseclib4\crypt\rsa' => self::KEYGEN,
        'phpseclib4\crypt\ec' => self::KEYGEN,
        'phpseclib4\crypt\dh' => self::EXCHANGE,
        'lcobucci\jwt\signer\rsa' => self::SIGNATURE,
        'lcobucci\jwt\signer\ecdsa' => self::SIGNATURE,
        'lcobucci\jwt\signer\eddsa' => self::SIGNATURE,
    ];

    /** JWT/JOSE algorithm names that rest on RSA or elliptic curves: RS256, PS384, ES256K, EdDSA... */
    private const JWT_ALGORITHM = '/^(?:(?:RS|PS|ES)(?:256|384|512)|ES256K|EdDSA)$/';

    /**
     * @param  string[]  $paths  files or folders, relative to $base or absolute
     * @return list<array{file: string, line: int, found: string, risk: string}>
     */
    public static function scan(array $paths, string $base): array
    {
        $findings = [];

        foreach ($paths as $path) {
            $full = str_starts_with($path, '/') ? $path : rtrim($base, '/').'/'.$path;

            foreach (self::phpFiles($full) as $file) {
                $relative = ltrim(str_replace(rtrim($base, '/'), '', $file), '/');

                foreach (self::scanSource((string) file_get_contents($file)) as $finding) {
                    $findings[] = ['file' => $relative] + $finding;
                }
            }
        }

        return $findings;
    }

    /**
     * @return list<array{line: int, found: string, risk: string}>
     */
    public static function scanSource(string $source): array
    {
        $tokens = array_values(array_filter(
            token_get_all($source),
            fn ($t) => ! is_array($t) || ! in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)
        ));

        $findings = [];

        foreach ($tokens as $i => $token) {
            if (! is_array($token)) {
                continue;
            }

            [$id, $text, $line] = $token;
            $previous = $tokens[$i - 1] ?? null;
            $next = $tokens[$i + 1] ?? null;

            if ($id === T_CONSTANT_ENCAPSED_STRING) {
                $value = substr($text, 1, -1);

                if (preg_match(self::JWT_ALGORITHM, $value)) {
                    $findings[] = ['line' => $line, 'found' => "'{$value}' (JWT algorithm)", 'risk' => self::SIGNATURE];
                }

                continue;
            }

            if (! in_array($id, [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)) {
                continue;
            }

            $name = strtolower(ltrim($text, '\\'));

            foreach (self::CLASSES as $prefix => $risk) {
                if (str_starts_with($name, $prefix)) {
                    $findings[] = ['line' => $line, 'found' => ltrim($text, '\\'), 'risk' => $risk];

                    continue 2;
                }
            }

            $isCall = $next === '(';
            $isMember = is_array($previous) && in_array($previous[0], [T_FUNCTION, T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_NEW, T_CONST], true);

            if ($isCall && ! $isMember && isset(self::FUNCTIONS[$name])) {
                $findings[] = ['line' => $line, 'found' => "{$name}()", 'risk' => self::FUNCTIONS[$name]];
            }
        }

        return $findings;
    }

    /**
     * @return iterable<string>
     */
    private static function phpFiles(string $path): iterable
    {
        if (is_file($path)) {
            return str_ends_with($path, '.php') ? [$path] : [];
        }

        if (! is_dir($path)) {
            return [];
        }

        $files = [];

        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)) as $file) {
            if ($file->isFile() && str_ends_with($file->getFilename(), '.php')) {
                $files[] = $file->getPathname();
            }
        }

        sort($files);

        return $files;
    }
}
