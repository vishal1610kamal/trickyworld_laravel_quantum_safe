<?php

namespace Tests\Unit;

use ParagonIE\PQCrypto\XWing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pqcrypto_compat ships Wycheproof tests for ML-KEM and ML-DSA but none for X-Wing, so this checks
 * its pure-PHP X-Wing against the test vectors published in the IETF draft itself.
 */
class XWingVectorsTest extends TestCase
{
    public static function vectors(): array
    {
        $file = json_decode(file_get_contents(__DIR__.'/../Fixtures/xwing-draft-11.json'), true);

        return array_map(fn ($v) => [$v], $file['vectors']);
    }

    #[DataProvider('vectors')]
    public function test_key_generation_matches_the_draft(array $v): void
    {
        [$secret, $public] = XWing::generateKeypairFromSeed(hex2bin($v['seed']));

        $this->assertSame($v['sk'], bin2hex($secret->bytes()));
        $this->assertSame($v['pk'], bin2hex($public->bytes()));
    }

    #[DataProvider('vectors')]
    public function test_encapsulation_matches_the_draft(array $v): void
    {
        $result = XWing::encapsulateDerandomized(hex2bin($v['pk']), hex2bin($v['eseed']));

        $this->assertSame($v['ct'], bin2hex($result['ciphertext']));
        $this->assertSame($v['ss'], bin2hex($result['sharedKey']));
    }

    #[DataProvider('vectors')]
    public function test_decapsulation_matches_the_draft(array $v): void
    {
        [$secret] = XWing::generateKeypairFromSeed(hex2bin($v['seed']));

        $this->assertSame($v['ss'], bin2hex(XWing::decapsulate($secret, hex2bin($v['ct']))));
    }
}
