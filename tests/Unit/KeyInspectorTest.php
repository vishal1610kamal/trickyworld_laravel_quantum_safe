<?php

namespace Tests\Unit;

use App\Crypto\Audit\KeyInspector;
use App\Crypto\Audit\Runtime;
use App\Crypto\Audit\TlsProbe;
use PHPUnit\Framework\TestCase;

class KeyInspectorTest extends TestCase
{
    private static function publicPem(array $options): string
    {
        $key = openssl_pkey_new($options);

        return openssl_pkey_get_details($key)['key'];
    }

    public function test_it_names_an_rsa_key_and_its_size(): void
    {
        $pem = self::publicPem(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

        $this->assertSame(['algorithm' => 'RSA', 'bits' => 2048, 'quantum_safe' => false], KeyInspector::inspect($pem));
    }

    public function test_it_names_an_elliptic_curve_key(): void
    {
        $pem = self::publicPem(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        $this->assertSame(['algorithm' => 'EC prime256v1', 'bits' => 256, 'quantum_safe' => false], KeyInspector::inspect($pem));
    }

    public function test_it_recognises_an_ml_dsa_public_key_without_openssl_support(): void
    {
        // SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.3.18 }, BIT STRING { 1,952-byte key } }
        $oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x12";
        $algorithm = "\x30\x0b".$oid;
        $bitString = "\x03\x82\x07\xa1\x00".str_repeat("\x2a", 1952);
        $der = "\x30\x82\x07\xb2".$algorithm.$bitString;
        $pem = "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END PUBLIC KEY-----\n";

        $this->assertSame(['algorithm' => 'ML-DSA-65', 'bits' => null, 'quantum_safe' => true], KeyInspector::inspect($pem));
    }

    public function test_unreadable_input_returns_null(): void
    {
        $this->assertNull(KeyInspector::inspect('not a key'));
    }

    public function test_runtime_reads_openssl_version_strings(): void
    {
        $this->assertFalse(Runtime::hasMlKem('OpenSSL 3.0.2 15 Mar 2022'));
        $this->assertFalse(Runtime::hasMlKem('OpenSSL/3.0.13'));
        $this->assertTrue(Runtime::hasMlKem('OpenSSL/3.5.9'));
        $this->assertTrue(Runtime::hasMlKem('OpenSSL 4.1.0 23 Oct 2026'));
        $this->assertNull(Runtime::hasMlKem('BoringSSL'));
        $this->assertNull(Runtime::hasMlKem(null));
        $this->assertNotNull(Runtime::opensslLibrary());
    }

    public function test_the_trace_parser_and_classifier(): void
    {
        $trace = TlsProbe::parse("fl=1\nh=www.cloudflare.com\ntls=TLSv1.3\nkex=X25519MLKEM768\n");

        $this->assertSame('X25519MLKEM768', $trace['kex']);
        $this->assertTrue(TlsProbe::isPostQuantum($trace['kex']));
        $this->assertFalse(TlsProbe::isPostQuantum('X25519'));
        $this->assertFalse(TlsProbe::isPostQuantum('P-256'));
        $this->assertNull(TlsProbe::isPostQuantum(null));
    }
}
