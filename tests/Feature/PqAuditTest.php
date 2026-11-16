<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class PqAuditTest extends TestCase
{
    private function audit(array $options = []): array
    {
        $exit = Artisan::call('pq:audit', $options + ['--json' => true]);
        $result = json_decode(Artisan::output(), true);
        $result['exit'] = $exit;
        $result['by'] = collect($result['checks'])->keyBy('check')->all();

        return $result;
    }

    public function test_laravel_default_encryption_is_reported_safe(): void
    {
        config(['app.cipher' => 'AES-256-CBC', 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);

        $this->assertSame('ok', $this->audit()['by']['Laravel encryption']['status']);
    }

    public function test_aes_128_is_information_not_a_failure(): void
    {
        config(['app.cipher' => 'AES-128-GCM', 'app.key' => 'base64:'.base64_encode(random_bytes(16))]);

        $this->assertSame('info', $this->audit()['by']['Laravel encryption']['status']);
    }

    public function test_a_classical_key_exchange_is_flagged(): void
    {
        Http::fake(['*' => Http::response("tls=TLSv1.3\nkex=X25519\n")]);

        $check = $this->audit(['--probe' => true])['by']['Outbound TLS'];

        $this->assertSame('todo', $check['status']);
        $this->assertStringContainsString('kex=X25519', $check['detail']);
    }

    public function test_a_hybrid_key_exchange_passes(): void
    {
        Http::fake(['*' => Http::response("tls=TLSv1.3\nkex=X25519MLKEM768\n")]);

        $this->assertSame('ok', $this->audit(['--probe' => true])['by']['Outbound TLS']['status']);
    }

    public function test_the_probe_only_runs_when_asked(): void
    {
        Http::fake();

        $this->assertSame('skip', $this->audit()['by']['Outbound TLS']['status']);
        Http::assertNothingSent();
    }

    public function test_an_rsa_passport_key_is_flagged(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        config(['passport.public_key' => openssl_pkey_get_details($key)['key']]);

        $check = $this->audit()['by']['Passport signing key'];

        $this->assertSame('todo', $check['status']);
        $this->assertStringContainsString('RSA-2048', $check['detail']);
    }

    public function test_the_scan_lists_findings_and_strict_mode_fails(): void
    {
        $result = $this->audit(['--path' => ['tests/Fixtures/legacy'], '--strict' => true]);

        $this->assertCount(5, $result['findings']);
        $this->assertSame('todo', $result['by']['Public-key code']['status']);
        $this->assertSame(1, $result['exit']);
    }

    public function test_this_apps_own_code_is_clean(): void
    {
        $this->assertSame('ok', $this->audit()['by']['Public-key code']['status']);
    }

    public function test_the_text_report_renders(): void
    {
        $this->artisan('pq:audit', ['--path' => ['tests/Fixtures/legacy']])
            ->expectsOutputToContain('Quantum-readiness audit')
            ->expectsOutputToContain('tests/Fixtures/legacy/RsaKycVault.php:16  openssl_seal()')
            ->assertExitCode(0);
    }
}
