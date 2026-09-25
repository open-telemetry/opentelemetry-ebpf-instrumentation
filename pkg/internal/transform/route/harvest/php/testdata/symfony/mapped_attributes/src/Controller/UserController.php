<?php

namespace App\Controller;

use Symfony\Component\Routing\Attribute\Route;

final class UserController
{
    #[Route('/users/{id}')]
    public function show(): void {}
}
