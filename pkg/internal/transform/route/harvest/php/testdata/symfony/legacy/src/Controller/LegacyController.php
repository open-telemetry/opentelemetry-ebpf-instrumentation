<?php

namespace AppBundle\Controller;

/** @Route("/legacy") */
class LegacyController
{
    /** @Route("/orders/{id}") */
    public function showAction($id) {}

    /** @Rest\Get("/status/{code}") */
    public function statusAction($code) {}
}
