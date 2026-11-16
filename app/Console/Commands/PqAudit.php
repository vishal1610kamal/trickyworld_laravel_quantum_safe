<?php

namespace App\Console\Commands;

use App\Crypto\Audit\CodeScanner;
use App\Crypto\Audit\KeyInspector;
use App\Crypto\Audit\Runtime;
use App\Crypto\Audit\TlsProbe;
use Illuminate\Console\Command;
use Laravel\Passport\Passport;
use Throwable;

class PqAudit extends Command
{
    protected $signature = 'pq:audit
        {--probe : Make one HTTPS request to the trace URL to see which key exchange PHP negotiates}
        {--path=* : Files or folders to scan instead of config("pq.scan_paths")}
        {--json : Print the result as JSON}
        {--strict : Exit with code 1 when anything is left to do}';

    protected $description = 'List what in this Laravel app a quantum computer could break, and what it could not';

    /** @var list<array{check: string, status: string, detail: string}> */
    private array $checks = [];

    public function handle(): int
    {
        $this->checkEncryption();
        $this->checkPasswords();
        $this->checkTlsLibrary();
        $this->checkOutboundTls();
        $this->checkPassportKey();

        $paths = $this->option('path') ?: config('pq.scan_paths', []);
        $findings = CodeScanner::scan($paths, base_path());

        $this->add('Public-key code', $findings ? 'todo' : 'ok', $findings
            ? count($findings).' place(s) in '.implode(', ', $paths).', listed below'
            : 'no RSA, elliptic-curve or JWT-signature code in '.implode(', ', $paths));

        if ($this->option('json')) {
            $this->line(json_encode(['checks' => $this->checks, 'findings' => $findings], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } else {
            $this->render($findings);
        }

        $todo = collect($this->checks)->contains('status', 'todo');

        return $this->option('strict') && $todo ? self::FAILURE : self::SUCCESS;
    }

    private function checkEncryption(): void
    {
        $cipher = strtoupper((string) config('app.cipher'));
        $key = (string) config('app.key');
        $bytes = strlen(str_starts_with($key, 'base64:') ? (string) base64_decode(substr($key, 7), true) : $key);

        if (str_starts_with($cipher, 'AES-256') && $bytes === 32) {
            $this->add('Laravel encryption', 'ok', "{$cipher} with a 32-byte key: symmetric, NIST's top post-quantum security category");
        } elseif (str_starts_with($cipher, 'AES-128')) {
            $this->add('Laravel encryption', 'info', "{$cipher}: NIST still approves AES-128 (category 1); CNSA 2.0 asks for AES-256");
        } else {
            $this->add('Laravel encryption', 'todo', "{$cipher} with a {$bytes}-byte key: use AES-256-CBC or AES-256-GCM with a 32-byte key");
        }
    }

    private function checkPasswords(): void
    {
        $driver = (string) config('hashing.driver', 'bcrypt');

        $this->add('Password hashing', 'ok', "{$driver}: not public-key cryptography, so Shor's algorithm does not apply");
    }

    private function checkTlsLibrary(): void
    {
        $library = Runtime::opensslLibrary();
        $curl = Runtime::curlTls();
        $mlkem = Runtime::hasMlKem($curl ?? $library);

        $detail = 'ext/openssl loads '.($library ?? 'nothing').'; ext/curl uses '.($curl ?? 'nothing');

        if ($library !== null && $library !== Runtime::opensslHeaders()) {
            $detail .= '; PHP was built against '.Runtime::opensslHeaders();
        }

        $this->add('TLS library', match ($mlkem) {
            true => 'ok',
            false => 'todo',
            null => 'info',
        }, $detail.match ($mlkem) {
            true => ' (has ML-KEM)',
            false => ' (no ML-KEM: OpenSSL 3.5 or later needed)',
            null => ' (not OpenSSL: run with --probe)',
        });
    }

    private function checkOutboundTls(): void
    {
        if (! $this->option('probe')) {
            $this->add('Outbound TLS', 'skip', 'run with --probe to test a real handshake');

            return;
        }

        $url = (string) config('pq.trace_url');

        try {
            $trace = TlsProbe::run($url);
        } catch (Throwable $e) {
            $this->add('Outbound TLS', 'info', "could not reach {$url}: ".$e->getMessage());

            return;
        }

        $kex = $trace['kex'] ?? null;
        $tls = $trace['tls'] ?? '?';

        $this->add('Outbound TLS', match (TlsProbe::isPostQuantum($kex)) {
            true => 'ok',
            false => 'todo',
            null => 'info',
        }, match (TlsProbe::isPostQuantum($kex)) {
            true => "{$tls}, kex={$kex}: hybrid post-quantum key exchange",
            false => "{$tls}, kex={$kex}: classical, so traffic recorded today could be decrypted later",
            null => "{$url} did not report the key exchange",
        });
    }

    private function checkPassportKey(): void
    {
        $pem = config('passport.public_key');
        $where = 'PASSPORT_PUBLIC_KEY';

        if (! $pem) {
            $path = class_exists(Passport::class)
                ? Passport::keyPath('oauth-public.key')
                : storage_path('oauth-public.key');
            $where = str_replace(base_path().'/', '', $path);
            $pem = is_readable($path) ? file_get_contents($path) : null;
        }

        if (! $pem) {
            $this->add('Passport signing key', 'skip', 'no Passport key found');

            return;
        }

        $key = KeyInspector::inspect($pem);

        if ($key === null) {
            $this->add('Passport signing key', 'info', "{$where} could not be read");
        } elseif ($key['quantum_safe']) {
            $this->add('Passport signing key', 'ok', "{$key['algorithm']} ({$where})");
        } else {
            $this->add('Passport signing key', 'todo', "{$key['algorithm']}-{$key['bits']} ({$where}): tokens become forgeable once a quantum computer exists; keep them short-lived and rotate the key");
        }
    }

    private function add(string $check, string $status, string $detail): void
    {
        $this->checks[] = compact('check', 'status', 'detail');
    }

    private function render(array $findings): void
    {
        $this->line('Quantum-readiness audit');
        $this->newLine();

        foreach ($this->checks as $c) {
            $this->line(sprintf('%-7s %-21s %s', "[{$c['status']}]", $c['check'], $c['detail']));
        }

        if ($findings) {
            $this->newLine();

            foreach ($findings as $f) {
                $this->line(sprintf('  %s:%d  %s  -> %s', $f['file'], $f['line'], $f['found'], $f['risk']));
            }
        }
    }
}
