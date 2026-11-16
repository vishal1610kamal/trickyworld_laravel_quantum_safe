<?php

namespace App\Casts;

use App\Crypto\HybridSealer;
use Illuminate\Contracts\Database\Eloquent\CastsInboundAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Seals an attribute with the public key when it is set, and leaves it sealed when read.
 *
 * Web servers that hold only the public key can store the value but never read it back. Open it
 * where the secret key lives:
 *
 *     app(HybridSealer::class)->open($model->pan, SealOnWrite::context($model, 'pan'));
 */
class SealOnWrite implements CastsInboundAttributes
{
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null || HybridSealer::isSealed($value)) {
            return $value;
        }

        return app(HybridSealer::class)->seal((string) $value, static::context($model, $key));
    }

    public static function context(Model $model, string $key): string
    {
        return $model->getTable().'.'.$key;
    }
}
