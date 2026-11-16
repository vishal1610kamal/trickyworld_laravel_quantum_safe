<?php

namespace App\Providers;

use App\Crypto\HybridSealer;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->singleton(HybridSealer::class, fn ($app) => HybridSealer::fromConfig($app['config']['pq']));
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
