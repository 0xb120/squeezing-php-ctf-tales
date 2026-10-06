# PHP 7.0.0 is the ONLY release that carries bug #71105: the fix landed in
# 7.0.1, so the tag below is load bearing - do not bump it.
FROM php:7.0.0-fpm

# jessie is long gone from deb.debian.org; nginx comes from the Debian archive.
RUN set -eux; \
    printf 'deb http://archive.debian.org/debian jessie main\n' > /etc/apt/sources.list; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid; \
    apt-get -o Acquire::Retries=3 update; \
    apt-get install -y --force-yes --no-install-recommends nginx-light; \
    rm -rf /var/lib/apt/lists/* /var/www/html

COPY conf/nginx.conf     /etc/nginx/nginx.conf
COPY conf/php-fpm.conf   /usr/local/etc/php-fpm.conf
COPY conf/fsop.ini       /usr/local/etc/php/conf.d/fsop.ini
COPY src/                /var/www/html/
COPY flag.txt            /flag.txt
COPY entrypoint.sh       /entrypoint.sh

# The flag is only readable by the process that renders the licence blob.
# There is no file-read primitive in this challenge; it has to come out of
# the worker's memory.
RUN set -eux; \
    chown root:www-data /flag.txt; chmod 0440 /flag.txt; \
    chmod -R a-w /var/www/html; \
    chmod 0755 /entrypoint.sh

EXPOSE 80
CMD ["/entrypoint.sh"]
