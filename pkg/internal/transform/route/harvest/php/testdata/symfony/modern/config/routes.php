<?php

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

return function (RoutingConfigurator $routes): void {
    $routes->add('from_php', '/from-php/{id}');
    $other->add('ignored', '/ignored');
};
