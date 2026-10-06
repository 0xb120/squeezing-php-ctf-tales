FROM php:7.4.33-apache

# Lay the container out like a XAMPP install so the paths in the challenge
# (C:\xampp\htdocs, C:\xampp\tmp) map 1:1 onto real directories. WinPath
# treats "C:" as the container root.
RUN set -eux; \
    mkdir -p /xampp/htdocs/statics/fonts /xampp/caches /xampp/tmp; \
    chown -R www-data:www-data /xampp/tmp /xampp/caches; \
    chmod 0755 /xampp/tmp /xampp/caches; \
    sed -ri 's!/var/www/html!/xampp/htdocs!g' \
        /etc/apache2/sites-available/000-default.conf; \
    sed -ri 's!<Directory /var/www/>!<Directory /xampp/htdocs/>!' \
        /etc/apache2/apache2.conf; \
    printf '%s\n' \
      'session.save_path = "/xampp/tmp"' \
      'session.use_cookies = 0' \
      'session.use_only_cookies = 0' \
      'session.use_strict_mode = 0' \
      'session.sid_length = 26' \
      'session.sid_bits_per_character = 5' \
      'expose_php = Off' \
      > /usr/local/etc/php/conf.d/zz-cms.ini

COPY src/ /xampp/htdocs/
RUN printf 'this is not a real TrueType font, it only needs to exist\n' \
      > /xampp/htdocs/statics/fonts/default.ttf; \
    printf 'PHRACK{dos_device_wildcards_leak_your_sessid}\n' > /flag.txt; \
    chmod 0644 /flag.txt

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["apache2-foreground"]
