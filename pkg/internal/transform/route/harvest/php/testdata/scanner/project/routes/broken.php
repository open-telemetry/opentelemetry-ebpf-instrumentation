<?php

use Illuminate\Support\Facades\Route;

Route::get('/broken', fn () => null);

if (true) {
