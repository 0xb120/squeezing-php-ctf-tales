FROM php:8.2.33-apache

# Deliberately vulnerable teaching material. Do not deploy.
COPY php.ini /usr/local/etc/php/conf.d/99-lab.ini
COPY src/ /var/www/html/

# The flag does NOT live here: the admin bot carries it in a cookie.
# This decoy makes that explicit for anyone who goes looking.
RUN printf 'the flag is not on this host. it is in the admin browser.\n' > /flag.txt \
 && chown -R www-data:www-data /var/www/html

EXPOSE 80
