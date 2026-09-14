<?php

use Illuminate\Support\Facades\Route;
use Slim\Factory\AppFactory;

Route::get('/laravel/{id}', fn () => null);

final class Controller
{
    #[Route('/symfony/{id}')]
    public function show(): void {}
}

$app = AppFactory::create();
$app->get('/slim/{id}', fn () => null);
