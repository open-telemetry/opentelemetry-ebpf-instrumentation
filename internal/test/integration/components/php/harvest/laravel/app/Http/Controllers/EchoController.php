<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;

final class EchoController
{
    public function show(string $echo): JsonResponse
    {
        return new JsonResponse(['value' => $echo]);
    }
}
