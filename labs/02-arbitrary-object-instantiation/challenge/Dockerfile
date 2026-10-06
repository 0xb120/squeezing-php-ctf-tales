# PluginHub front-end: PHP 7.4.33 + ext-soap.
FROM php:7.4.33-apache

# Bullseye is archived; pin the sources so the build stays reproducible.
RUN set -eux; \
    printf 'deb http://archive.debian.org/debian bullseye main\n' > /etc/apt/sources.list; \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid; \
    apt-get update; \
    apt-get install -y --no-install-recommends libxml2-dev; \
    docker-php-ext-install -j1 soap; \
    apt-get purge -y libxml2-dev; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

COPY php.ini /usr/local/etc/php/conf.d/pluginhub.ini
COPY src/ /var/www/html/

# The package cache lives OUTSIDE the web root; index.php serves it explicitly.
RUN mkdir -p /var/www/pkgcache \
 && chown -R www-data:www-data /var/www/pkgcache \
 && printf 'ServerName pluginhub.local\n' > /etc/apache2/conf-available/servername.conf \
 && a2enconf servername \
 && rm -f /var/www/html/index.html

EXPOSE 80
