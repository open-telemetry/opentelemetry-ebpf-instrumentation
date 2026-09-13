<?php

$app = new \Slim\App();
$app->group('/v3', function () {
    $this->get('/things/{id}', function () {});
});

$this->get('/ignored', function () {});
