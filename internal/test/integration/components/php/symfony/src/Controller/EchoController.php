<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

final class EchoController
{
    #[Route('/api/echo/{value}', methods: ['GET'])]
    public function path(Request $request, string $value): JsonResponse
    {
        return new JsonResponse([
            'value' => $value,
            'query' => $request->query->all(),
        ]);
    }
}
