FROM php:8.1.34-apache

RUN docker-php-ext-install -j"$(nproc)" mysqli \
 && printf 'display_errors=Off\nlog_errors=On\nerror_log=/dev/stderr\n' \
      > /usr/local/etc/php/conf.d/zz-lab.ini

COPY src/ /var/www/html/
COPY flag.txt /flag.txt

RUN chmod 0444 /flag.txt \
 && mkdir -p /var/inkpress \
 && chown -R www-data:www-data /var/inkpress

EXPOSE 80
