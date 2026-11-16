<?php

namespace App\Console\Commands;

use App\Crypto\HybridSealer;
use Illuminate\Console\Command;

class PqKeygen extends Command
{
    protected $signature = 'pq:keygen
        {--path= : Where to write the secret key (default: storage/pq-seal.key)}
        {--force : Overwrite an existing secret key file}';

    protected $description = 'Create an X-Wing (ML-KEM-768 + X25519) key pair for sealing values';

    public function handle(): int
    {
        $path = $this->option('path') ?: storage_path('pq-seal.key');

        if (file_exists($path) && ! $this->option('force')) {
            $this->error("{$path} already exists. Values sealed to it would become unreadable: use --force only if you mean it.");

            return self::FAILURE;
        }

        $keys = HybridSealer::generateKeys();

        $old = umask(0077);
        $written = file_put_contents($path, base64_encode($keys['secret']).PHP_EOL);
        umask($old);

        if ($written === false) {
            $this->error("Could not write {$path}.");

            return self::FAILURE;
        }

        chmod($path, 0600);

        $this->info("Secret key written to {$path} (mode 0600). Copy it only to the machine that opens sealed values,");
        $this->info('back it up offline, then set PQ_SEAL_SECRET_KEY_PATH there.');
        $this->newLine();
        $this->line('Add this line to .env on every server that seals values:');
        $this->newLine();
        $this->line('PQ_SEAL_PUBLIC_KEY='.base64_encode($keys['public']));

        return self::SUCCESS;
    }
}
