<?php

namespace AmranIbrahem\JWTSetup;

use Illuminate\Support\ServiceProvider;
use AmranIbrahem\JWTSetup\Commands\InstallJWTCommand;

class JWTServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->commands([
            InstallJWTCommand::class,
        ]);
    }

    public function boot()
    {

    }
}
