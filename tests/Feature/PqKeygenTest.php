<?php

namespace Tests\Feature;

use App\Crypto\HybridSealer;
use Illuminate\Support\Facades\Artisan;
use Tests\TestCase;

class PqKeygenTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        parent::setUp();
        $this->path = sys_get_temp_dir().'/pq-keygen-'.bin2hex(random_bytes(4)).'.key';
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
        parent::tearDown();
    }

    public function test_it_writes_a_private_secret_key_and_prints_a_working_public_key(): void
    {
        $this->assertSame(0, Artisan::call('pq:keygen', ['--path' => $this->path]));

        preg_match('/^PQ_SEAL_PUBLIC_KEY=(\S+)$/m', Artisan::output(), $m);

        $this->assertSame('0600', substr(sprintf('%o', fileperms($this->path)), -4));

        $sealer = HybridSealer::fromConfig(['public_key' => $m[1], 'secret_key_path' => $this->path]);
        $this->assertSame('it works', $sealer->open($sealer->seal('it works')));
    }

    public function test_it_will_not_overwrite_a_key_without_force(): void
    {
        file_put_contents($this->path, 'existing');

        $this->assertSame(1, Artisan::call('pq:keygen', ['--path' => $this->path]));
        $this->assertSame('existing', file_get_contents($this->path));
    }
}
