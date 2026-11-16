<?php

namespace Tests\Unit;

use App\Crypto\Audit\CodeScanner;
use PHPUnit\Framework\TestCase;

class CodeScannerTest extends TestCase
{
    public function test_it_finds_the_public_key_code_in_the_fixtures_and_nothing_else(): void
    {
        $findings = CodeScanner::scan(['tests/Fixtures/legacy'], dirname(__DIR__, 2));

        $this->assertSame([
            'tests/Fixtures/legacy/PartnerWebhook.php:15 \'RS256\' (JWT algorithm)',
            'tests/Fixtures/legacy/PartnerWebhook.php:20 openssl_verify()',
            'tests/Fixtures/legacy/PartnerWebhook.php:25 \'RS256\' (JWT algorithm)',
            'tests/Fixtures/legacy/RsaKycVault.php:16 openssl_seal()',
            'tests/Fixtures/legacy/RsaKycVault.php:25 openssl_open()',
        ], array_map(fn ($f) => "{$f['file']}:{$f['line']} {$f['found']}", $findings));
    }

    public function test_signatures_and_key_exchange_carry_different_risks(): void
    {
        $findings = CodeScanner::scanSource('<?php openssl_sign($a, $s, $k); sodium_crypto_box_seal($m, $pk);');

        $this->assertStringContainsString('forged', $findings[0]['risk']);
        $this->assertStringContainsString('recorded today', $findings[1]['risk']);
    }

    public function test_it_ignores_comments_strings_methods_and_definitions(): void
    {
        $source = <<<'PHP'
        <?php
        // openssl_public_encrypt($data, $out, $key);
        /* sodium_crypto_box_seal($m, $pk); */
        $name = 'openssl_sign';
        $client->openssl_sign($x);
        Signer::openssl_verify($x);
        function openssl_seal_wrapper() {}
        $ok = function_exists('openssl_pkey_new');
        $mac = hash_hmac('sha256', $body, $key);
        $value = Crypt::encryptString('secret');
        $alg = 'HS256';
        PHP;

        $this->assertSame([], CodeScanner::scanSource($source));
    }

    public function test_it_finds_rsa_and_ec_classes_and_key_generation(): void
    {
        $source = <<<'PHP'
        <?php
        use phpseclib3\Crypt\RSA;
        use Lcobucci\JWT\Signer\Ecdsa\Sha256;
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $alg = 'ES256';
        PHP;

        $found = array_column(CodeScanner::scanSource($source), 'found');

        $this->assertSame(['phpseclib3\Crypt\RSA', 'Lcobucci\JWT\Signer\Ecdsa\Sha256', 'openssl_pkey_new()', "'ES256' (JWT algorithm)"], $found);
    }

    public function test_the_app_folder_of_this_repository_is_clean(): void
    {
        $this->assertSame([], CodeScanner::scan(['app', 'config', 'routes', 'database'], dirname(__DIR__, 2)));
    }
}
