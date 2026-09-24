<?php

use Illuminate\Support\Facades\Route;

Route::singleton('profile', ProfileController::class);
Route::apiSingleton('settings', SettingsController::class);
Route::singleton('account', AccountController::class)->creatable();
Route::softDeletableResources(
    ['posts' => PostController::class],
    ['only' => ['show']],
);
