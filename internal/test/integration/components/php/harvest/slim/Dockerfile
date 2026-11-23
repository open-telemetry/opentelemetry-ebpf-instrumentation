FROM composer:2.11@sha256:537fb03057ed901ae06bde7ef25af348903485ae1acc7fc789b80d8bac666f35 AS dependencies

WORKDIR /app
COPY internal/test/integration/components/php/harvest/slim/composer.json internal/test/integration/components/php/harvest/slim/composer.lock ./
RUN composer install --no-dev --no-interaction --no-scripts --prefer-dist

FROM php:8.5.8-fpm@sha256:0dc450d0a0e81ba501973b8e303f5d45af2ed989e08730f597d8fc07fb289efd

WORKDIR /var/www/slim
COPY --from=dependencies /app/vendor ./vendor
COPY internal/test/integration/components/php/harvest/slim/composer.json internal/test/integration/components/php/harvest/slim/composer.lock ./
COPY internal/test/integration/components/php/harvest/slim/public ./public
COPY internal/test/integration/components/php/harvest/php-fpm.conf /usr/local/etc/php-fpm.d/www.conf
