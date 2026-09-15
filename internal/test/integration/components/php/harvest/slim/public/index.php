<?php

use Psr\Http\Message\ResponseInterface;
use Slim\Factory\AppFactory;
use Slim\Routing\RouteCollectorProxy;

require __DIR__.'/../vendor/autoload.php';

$app = AppFactory::create();
$app->setBasePath('/slim');
$app->group('/api', function (RouteCollectorProxy $group): void {
    $group->get('/echo/{value:[a-z]+}', function ($request, ResponseInterface $response, array $args): ResponseInterface {
        $response->getBody()->write(json_encode(['value' => $args['value']], JSON_THROW_ON_ERROR));
        return $response->withHeader('Content-Type', 'application/json');
    });
});
$app->run();
