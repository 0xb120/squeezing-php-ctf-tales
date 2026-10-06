FROM php:8.1.34-apache

COPY php.ini /usr/local/etc/php/conf.d/zz-minipress.ini
COPY src/ /var/www/html/
COPY flag.txt /flag.txt
COPY flag-sqli.txt /flag-sqli.txt

# The SQLite database is seeded at BUILD time.  /flag-sqli.txt is read exactly
# once, by minipress-metatools' installer, and deleted in the same layer's
# command: at run time the second flag exists only as a wpl_productmeta row,
# so the only way to it is the SQL injection.
RUN set -eux; \
    php -r 'exit(extension_loaded("pdo_sqlite") ? 0 : 1);'; \
    mkdir -p /var/lib/minipress; \
    php -r 'require "/var/www/html/bootstrap.php";'; \
    test -s /var/lib/minipress/minipress.sqlite; \
    rm -f /flag-sqli.txt; \
    chown -R www-data:www-data /var/lib/minipress; \
    chown root:www-data /flag.txt; \
    chmod 0640 /flag.txt

HEALTHCHECK --interval=3s --timeout=3s --retries=20 \
  CMD php -r '$c=@file_get_contents("http://127.0.0.1/index.php");exit($c===false?1:0);'
