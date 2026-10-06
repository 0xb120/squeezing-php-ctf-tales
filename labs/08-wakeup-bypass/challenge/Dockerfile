# The "today" build: a PHP that is immune to CVE-2016-7124.
FROM php:8.2.33-apache

RUN printf 'display_errors=Off\nlog_errors=On\nerror_log=/dev/stderr\n' \
      > /usr/local/etc/php/conf.d/zz-lab.ini

COPY src/      /var/www/html/
COPY flag.txt  /flag.txt

RUN chmod 0444 /flag.txt \
 && mkdir -p /var/postbox \
 && chown -R www-data:www-data /var/postbox

EXPOSE 80
