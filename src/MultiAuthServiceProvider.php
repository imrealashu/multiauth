<?php

namespace Imrealashu\MultiAuthGenerator;

use Illuminate\Support\ServiceProvider;

class MultiAuthServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        $this->commands([
            'Imrealashu\MultiAuthGenerator\Console\MultiAuthNewCommand',
            'Imrealashu\MultiAuthGenerator\Console\MultiAuthClearCommand'
        ]);
    }
}
