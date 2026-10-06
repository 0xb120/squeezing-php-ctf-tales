FROM php:8.1.34-apache

COPY php.ini /usr/local/etc/php/conf.d/zz-vault.ini
COPY src/ /var/www/html/
COPY flag.txt /flag.txt

# the 1x1 placeholder avatar shipped with the app
RUN set -eux; \
    mkdir -p /var/www/html/assets /var/www/html/thumbs /var/lib/vault/sess /var/lib/vault/profiles /var/lib/vault/pw; \
    printf '%s' 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==' \
      | base64 -d > /var/www/html/assets/default.png; \
    chown -R www-data:www-data /var/lib/vault /var/www/html/thumbs; \
    chown root:www-data /flag.txt; \
    chmod 0640 /flag.txt

HEALTHCHECK --interval=3s --timeout=3s --retries=20 \
  CMD php -r '$c=@file_get_contents("http://127.0.0.1/index.php");exit($c===false?1:0);'
