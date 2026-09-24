<?php

use App\Http\Controllers\EchoController;
use Illuminate\Support\Facades\Route;

Route::apiResource('echo', EchoController::class)->only('show');
