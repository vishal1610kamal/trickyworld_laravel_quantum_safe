<?php

namespace Tests\Unit;

use App\Crypto\HybridSealer;
use Illuminate\Contracts\Encryption\DecryptException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class HybridSealerTest extends TestCase
{
    private static array $keys;

    public static function setUpBeforeClass(): void
    {
        self::$keys = HybridSealer::generateKeys();
    }

    private function sealer(bool $withSecret = true): HybridSealer
    {
        return new HybridSealer(self::$keys['public'], $withSecret ? self::$keys['secret'] : null);
    }

    public function test_keys_have_the_x_wing_sizes(): void
    {
        $this->assertSame(1216, strlen(self::$keys['public']));
        $this->assertSame(32, strlen(self::$keys['secret']));
    }

    public function test_a_sealed_value_opens_with_the_same_context(): void
    {
        $sealed = $this->sealer()->seal('ABCDE1234F', 'kyc_records.pan');

        $this->assertStringStartsWith('pq1:', $sealed);
        $this->assertStringNotContainsString('ABCDE1234F', $sealed);
        $this->assertSame('ABCDE1234F', $this->sealer()->open($sealed, 'kyc_records.pan'));
    }

    public function test_every_seal_is_different(): void
    {
        $this->assertNotSame($this->sealer()->seal('same'), $this->sealer()->seal('same'));
    }

    public function test_a_public_key_only_sealer_seals_but_cannot_open(): void
    {
        $sealed = $this->sealer(withSecret: false)->seal('ABCDE1234F');

        $this->assertFalse($this->sealer(withSecret: false)->canOpen());
        $this->assertSame('ABCDE1234F', $this->sealer()->open($sealed));

        $this->expectException(RuntimeException::class);
        $this->sealer(withSecret: false)->open($sealed);
    }

    public function test_another_context_is_rejected(): void
    {
        $sealed = $this->sealer()->seal('ABCDE1234F', 'kyc_records.pan');

        $this->expectException(DecryptException::class);
        $this->sealer()->open($sealed, 'users.notes');
    }

    public function test_a_changed_x_wing_ciphertext_is_rejected(): void
    {
        $sealed = $this->sealer()->seal('ABCDE1234F');
        [$kem, $payload] = explode(':', substr($sealed, 4), 2);

        $bytes = base64_decode($kem);
        $bytes[100] = chr(ord($bytes[100]) ^ 1);

        $this->expectException(DecryptException::class);
        $this->sealer()->open('pq1:'.base64_encode($bytes).':'.$payload);
    }

    public function test_a_changed_payload_is_rejected(): void
    {
        $sealed = $this->sealer()->seal('ABCDE1234F');
        $json = json_decode(base64_decode(substr($sealed, strrpos($sealed, ':') + 1)), true);
        $json['value'] = base64_encode(strrev(base64_decode($json['value'])));
        $forged = substr($sealed, 0, strrpos($sealed, ':') + 1).base64_encode(json_encode($json));

        $this->expectException(DecryptException::class);
        $this->sealer()->open($forged);
    }

    public function test_a_value_sealed_to_another_key_is_rejected(): void
    {
        $other = HybridSealer::generateKeys();
        $sealed = (new HybridSealer($other['public']))->seal('ABCDE1234F');

        $this->expectException(DecryptException::class);
        $this->sealer()->open($sealed);
    }

    public function test_a_secret_key_from_another_pair_is_refused_up_front(): void
    {
        $other = HybridSealer::generateKeys();

        $this->expectExceptionMessage('does not belong');
        new HybridSealer(self::$keys['public'], $other['secret']);
    }

    public function test_malformed_input_is_rejected(): void
    {
        foreach (['ABCDE1234F', 'pq1:not-base64!:x', 'pq1:'.base64_encode('short').':x'] as $bad) {
            try {
                $this->sealer()->open($bad);
                $this->fail("Opened {$bad}");
            } catch (DecryptException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function test_from_config_reads_the_secret_key_file(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'pq');
        file_put_contents($path, base64_encode(self::$keys['secret'])."\n");

        $sealer = HybridSealer::fromConfig([
            'public_key' => base64_encode(self::$keys['public']),
            'secret_key_path' => $path,
        ]);
        unlink($path);

        $this->assertTrue($sealer->canOpen());
        $this->assertSame('x', $sealer->open($sealer->seal('x')));
    }
}
