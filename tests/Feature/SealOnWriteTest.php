<?php

namespace Tests\Feature;

use App\Casts\SealOnWrite;
use App\Crypto\HybridSealer;
use App\Models\KycRecord;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use RuntimeException;
use Tests\TestCase;

class SealOnWriteTest extends TestCase
{
    use RefreshDatabase;

    private array $keys;

    protected function setUp(): void
    {
        parent::setUp();

        $this->keys = HybridSealer::generateKeys();
        // The web tier: public key only.
        $this->app->instance(HybridSealer::class, new HybridSealer($this->keys['public']));
    }

    public function test_the_pan_is_sealed_in_the_database_and_on_the_model(): void
    {
        $record = KycRecord::create(['name' => 'Asha', 'pan' => 'ABCDE1234F']);

        $stored = DB::table('kyc_records')->value('pan');

        $this->assertStringStartsWith('pq1:', $stored);
        $this->assertStringNotContainsString('ABCDE1234F', $stored);
        $this->assertSame($stored, $record->fresh()->pan);
    }

    public function test_the_web_tier_cannot_read_it_back(): void
    {
        $record = KycRecord::create(['name' => 'Asha', 'pan' => 'ABCDE1234F']);

        $this->expectException(RuntimeException::class);
        app(HybridSealer::class)->open($record->pan, SealOnWrite::context($record, 'pan'));
    }

    public function test_the_back_office_opens_it_with_the_table_and_column_as_context(): void
    {
        $record = KycRecord::create(['name' => 'Asha', 'pan' => 'ABCDE1234F'])->fresh();

        $backOffice = new HybridSealer($this->keys['public'], $this->keys['secret']);

        $this->assertSame('ABCDE1234F', $backOffice->open($record->pan, SealOnWrite::context($record, 'pan')));
        $this->assertSame('kyc_records.pan', SealOnWrite::context($record, 'pan'));
    }

    public function test_saving_again_does_not_seal_twice(): void
    {
        $record = KycRecord::create(['name' => 'Asha', 'pan' => 'ABCDE1234F'])->fresh();
        $sealed = $record->pan;

        $record->pan = $record->pan;
        $record->name = 'Asha R';
        $record->save();

        $this->assertSame($sealed, DB::table('kyc_records')->value('pan'));
    }

    public function test_a_sealed_value_is_about_1_6_kb(): void
    {
        $record = KycRecord::create(['name' => 'Asha', 'pan' => 'ABCDE1234F']);

        $length = strlen(DB::table('kyc_records')->value('pan'));

        $this->assertGreaterThan(1600, $length);
        $this->assertLessThan(1800, $length);
    }
}
