<?php

use Slim\Factory\AppFactory;
use Slim\Routing\RouteCollectorProxy;

$app = AppFactory::create();
$app->setBasePath('/service');
$app->group('/api', function (RouteCollectorProxy $group) {
    $group->get('/users/{id:[0-9]+}', fn () => null);
    $group->group('/nested', function ($router) {
        $router->post('/echo/{value}', fn () => null);
    });
});

$other->get('/ignored', fn () => null);
