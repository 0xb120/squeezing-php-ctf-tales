FROM php:7.4.33-apache

# The whole point of the lab: PHP 7.4 still unserializes PHAR metadata
# automatically inside the phar:// stream wrapper.
#
# Both phar ini settings are left at their *defaults* on purpose:
#   phar.readonly   = 1   -> creating a phar from PHP is forbidden (does NOT
#                            stop the attack: we only *read* one)
#   phar.require_hash = 1 -> the archive must carry a valid signature
RUN { \
      echo 'display_errors=Off'; \
      echo 'log_errors=On'; \
      echo 'error_log=/dev/stderr'; \
      echo 'upload_max_filesize=256K'; \
      echo 'post_max_size=512K'; \
    } > /usr/local/etc/php/conf.d/zz-lab.ini

COPY src/ /var/www/html/
COPY flag.txt /flag.txt

RUN chmod 444 /flag.txt \
 && mkdir -p /var/www/html/uploads /var/www/html/data \
 && chown www-data:www-data /var/www/html/uploads /var/www/html/data \
 && chmod 755 /var/www/html/uploads /var/www/html/data

HEALTHCHECK --interval=2s --timeout=3s --retries=30 \
  CMD php -r 'exit(@file_get_contents("http://127.0.0.1/") ? 0 : 1);'
