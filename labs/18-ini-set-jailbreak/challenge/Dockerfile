# PHP 8.2.33 / Debian 13 (trixie) / mod_php on Apache 2.4 (mpm_prefork).
FROM php:8.2.33-apache

COPY conf/zz-sandbox.ini /usr/local/etc/php/conf.d/zz-sandbox.ini
COPY conf/sandbox.conf   /etc/apache2/conf-enabled/sandbox.conf
COPY src/index.php       /var/www/html/index.php
COPY src/jail/run.php    /var/www/sandbox/run.php
COPY flag.txt            /flag.txt

RUN set -eux; \
    chown root:root /flag.txt /var/www/sandbox/run.php; \
    chmod 0644      /flag.txt /var/www/sandbox/run.php; \
    # Scratch space for the playground: world writable *and sticky*, exactly
    # like /tmp.  Sandboxed code may create files, but cannot unlink the
    # root-owned evaluator sitting next to them.
    chmod 1777 /var/www/sandbox; \
    rm -f /var/www/html/index.html

EXPOSE 80
