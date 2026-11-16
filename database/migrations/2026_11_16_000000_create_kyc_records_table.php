<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('kyc_records', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            // A sealed value is about 1.6 KB however short the input: the X-Wing ciphertext alone is 1,120 bytes.
            $table->text('pan');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('kyc_records');
    }
};
