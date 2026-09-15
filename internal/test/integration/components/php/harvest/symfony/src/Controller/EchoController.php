<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/api/symfony')]
final class EchoController
{
    #[Route('/echo/{value}', methods: ['GET'])]
    public function echo(string $value): JsonResponse
    {
        return new JsonResponse(['value' => $value]);
    }
}
