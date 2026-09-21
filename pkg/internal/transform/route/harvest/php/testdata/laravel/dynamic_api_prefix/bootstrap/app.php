<?php

use Illuminate\Foundation\Application;

return Application::configure()
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        apiPrefix: configuredPrefix(),
    )->create();
