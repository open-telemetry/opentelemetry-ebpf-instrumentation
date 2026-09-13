<?php

namespace App\ApiResource;

#[ApiResource(
    uriTemplate: '/library/books/{id}',
    operations: [new Get(uriTemplate: '/library/public-books/{id}')],
)]
final class Book {}
