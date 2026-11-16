<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Sealing keys (X-Wing: ML-KEM-768 + X25519)
    |--------------------------------------------------------------------------
    |
    | The public key may live on every web server: it can seal values but
    | never open them. Only the process that has to read sealed values (a
    | back-office worker, say) needs the secret key file. Create both with
    | "php artisan pq:keygen".
    |
    */

    'public_key' => env('PQ_SEAL_PUBLIC_KEY'),

    'secret_key_path' => env('PQ_SEAL_SECRET_KEY_PATH'),

    /*
    |--------------------------------------------------------------------------
    | pq:audit
    |--------------------------------------------------------------------------
    |
    | trace_url must answer with Cloudflare's /cdn-cgi/trace format, whose
    | "kex=" line names the key exchange this PHP process negotiated. It is
    | only contacted when you run "php artisan pq:audit --probe".
    |
    */

    'trace_url' => env('PQ_TRACE_URL', 'https://www.cloudflare.com/cdn-cgi/trace'),

    'scan_paths' => ['app', 'config', 'routes', 'database'],

];
