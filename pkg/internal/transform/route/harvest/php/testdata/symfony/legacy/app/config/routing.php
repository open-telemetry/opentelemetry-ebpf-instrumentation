<?php

use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

$routes = new RouteCollection();
$routes->add('legacy_php', new Route('/legacy-php/{id}'));

return $routes;
