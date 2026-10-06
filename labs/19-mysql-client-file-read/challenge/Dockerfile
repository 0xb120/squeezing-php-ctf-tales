# PHP 7.4.33 / Debian 11 (bullseye) / mod_php on Apache 2.4.
# mysqli is built against the bundled mysqlnd driver (no libmysqlclient).
FROM php:7.4.33-apache

RUN docker-php-ext-install -j"$(nproc)" mysqli > /dev/null

COPY conf/zz-app.ini /usr/local/etc/php/conf.d/zz-app.ini
COPY src/            /var/www/html/
COPY flag.txt        /flag.txt

RUN set -eux; \
    chown root:root /flag.txt; chmod 0644 /flag.txt; \
    mkdir -p /var/www/html/uploads; \
    chown www-data:www-data /var/www/html/uploads; \
    chmod 0755 /var/www/html/uploads; \
    rm -f /var/www/html/index.html

EXPOSE 80
