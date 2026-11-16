<?php

namespace App\Models;

use App\Casts\SealOnWrite;
use Illuminate\Database\Eloquent\Model;

/**
 * A customer's PAN (Indian tax ID), sealed the moment it is set. The web servers that collect it
 * hold only the public key; the back-office worker that verifies it holds the secret key.
 */
class KycRecord extends Model
{
    protected $fillable = ['name', 'pan'];

    protected function casts(): array
    {
        return [
            'pan' => SealOnWrite::class,
        ];
    }
}
