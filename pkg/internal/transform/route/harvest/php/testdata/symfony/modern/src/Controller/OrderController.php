<?php

namespace App\Controller;

#[Route('/api')]
final class OrderController
{
    #[Route('/orders/{id<\\d+>}')]
    public function show(string $id): void {}

    #[Route(path: 'health/')]
    public function health(): void {}

    #[Other('/ignored')]
    public function ignored(): void {}
}
