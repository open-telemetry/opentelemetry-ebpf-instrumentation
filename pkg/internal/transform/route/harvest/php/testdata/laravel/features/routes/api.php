<?php

use Illuminate\Support\Facades\Route as Router;

Router::prefix('v1')->group(function () {
    Router::apiResource('users', UserController::class)->only(['index', 'show']);
    Router::get('status', fn () => null);
});

Router::group(['prefix' => 'admin'], function () {
    Router::get('audit', fn () => null);
});

Router::resource('photos.comments', CommentController::class)
    ->shallow()
    ->except('destroy');

Router::redirect('old', 'new');
Router::fallback(fn () => null);
Other::get('/ignored', fn () => null);
Router::get($dynamicPath, fn () => null);
