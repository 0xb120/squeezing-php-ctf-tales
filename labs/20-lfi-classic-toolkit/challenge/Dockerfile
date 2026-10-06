# ---------------------------------------------------------------------------
# The "modern wing": exhibits 2, 3 and 4 on a current interpreter.
#
# php:8.2.33-apache is deliberately *not* an old build.  The point of this
# lab is that only Exhibit 1 (path truncation) died: loose base64 decoding in
# php://filter, the zip:// wrapper and the RFC1867 temporary-file race all
# still work exactly as they did in 2009, 2015 and 2011 respectively.
# ---------------------------------------------------------------------------
FROM php:8.2.33-apache

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libzip-dev; \
    docker-php-ext-install -j"$(nproc)" zip; \
    apt-get purge -y libzip-dev; \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# php.ini.  The interesting part is what is switched OFF: every URL wrapper
# is disabled and there is still nothing standing between the player and
# code execution, because php:// and zip:// are not "URL" wrappers as far as
# allow_url_include is concerned.
#
# session.upload_progress is off on purpose - that is lab 11's trick, and the
# dot filter on exhibit 4 would otherwise accept sess_<id> as a payload file.
# ---------------------------------------------------------------------------
RUN set -eux; \
    { \
      echo 'allow_url_fopen = Off'; \
      echo 'allow_url_include = Off'; \
      echo 'file_uploads = On'; \
      echo 'upload_tmp_dir = /tmp'; \
      echo 'upload_max_filesize = 8M'; \
      echo 'post_max_size = 8M'; \
      echo 'max_file_uploads = 20'; \
      echo 'session.upload_progress.enabled = Off'; \
      echo 'session.auto_start = Off'; \
      echo 'expose_php = Off'; \
      echo 'display_errors = Off'; \
      echo 'log_errors = On'; \
      echo 'error_reporting = E_ALL & ~E_WARNING & ~E_NOTICE & ~E_DEPRECATED'; \
    } > /usr/local/etc/php/conf.d/zz-museum.ini

COPY src/ /var/www/html/
COPY museum-apache.conf /etc/apache2/conf-enabled/museum.conf
COPY readflag.c /tmp/readflag.c
COPY flag.txt /flag.txt

# The curator key is fragment1:fragment2:fragment3.  Only its SHA-256 is
# stored on this container, so owning the modern wing does not hand you
# fragment 1 - that one lives in the legacy wing and nowhere else.
RUN set -eux; \
    mkdir -p /opt/museum/keys /var/www/html/notes /var/www/html/uploads; \
    printf 'k2-base64-5c7e93ab\n' > /opt/museum/keys/stage2.key; \
    printf 'k3-zipwrap-1d6b04fe\n' > /opt/museum/keys/stage3.key; \
    chmod 0444 /opt/museum/keys/stage2.key /opt/museum/keys/stage3.key; \
    printf 'MUSEUM_WING=modern\n' > /opt/museum/wing; \
    printf '%s' 'k1-nulbyte-8f2a41d0:k2-base64-5c7e93ab:k3-zipwrap-1d6b04fe' \
      | sha256sum | cut -d' ' -f1 > /opt/museum/curator.hash; \
    chmod 0444 /opt/museum/curator.hash; \
    gcc -O2 -static -o /readflag /tmp/readflag.c; \
    rm -f /tmp/readflag.c; \
    chown root:root /readflag /flag.txt; \
    chmod 4755 /readflag; \
    chmod 0400 /flag.txt; \
    chown -R root:root /var/www/html; \
    chmod 0555 /var/www/html /var/www/html/exhibits; \
    chown www-data:www-data /var/www/html/notes /var/www/html/uploads; \
    chmod 0755 /var/www/html/notes /var/www/html/uploads
