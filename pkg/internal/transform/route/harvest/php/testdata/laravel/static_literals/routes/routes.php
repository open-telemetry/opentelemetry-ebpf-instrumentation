<?php

use Illuminate\Support\Facades\Route;

Route::get('/single', fn () => null);
Route::get("/double", fn () => null);
Route::get("/users/$id", fn () => null);
Route::get('/joined/'.'path', fn () => null);
Route::get(ROUTE_PATH, fn () => null);
Route::get(<<<ROUTE
/heredoc
ROUTE, fn () => null);
