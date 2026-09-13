FROM composer:2.8@sha256:5248900ab8b5f7f880c2d62180e40960cd87f60149ec9a1abfd62ac72a02577c AS dependencies

WORKDIR /app
COPY internal/test/integration/components/php/harvest/laravel/composer.json internal/test/integration/components/php/harvest/laravel/composer.lock ./
RUN composer install --no-dev --no-interaction --no-scripts --prefer-dist

FROM php:8.5.8-fpm@sha256:0dc450d0a0e81ba501973b8e303f5d45af2ed989e08730f597d8fc07fb289efd

WORKDIR /var/www/laravel
COPY --from=dependencies /app/vendor ./vendor
COPY internal/test/integration/components/php/harvest/laravel/composer.json internal/test/integration/components/php/harvest/laravel/composer.lock ./
COPY internal/test/integration/components/php/harvest/laravel/app ./app
COPY internal/test/integration/components/php/harvest/laravel/bootstrap ./bootstrap
COPY internal/test/integration/components/php/harvest/laravel/public ./public
COPY internal/test/integration/components/php/harvest/laravel/routes ./routes
COPY internal/test/integration/components/php/harvest/php-fpm.conf /usr/local/etc/php-fpm.d/www.conf
RUN mkdir -p bootstrap/cache storage/framework/cache storage/framework/sessions storage/framework/views storage/logs && chown -R www-data:www-data bootstrap/cache storage
