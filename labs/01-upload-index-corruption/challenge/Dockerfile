# ---------------------------------------------------------------------------
# Stage 1 - build PHP 5.3.10 from source.
#
# 5.3.10 is the last release whose main/rfc1867.c accepts multipart field
# names with unbalanced square brackets; 5.3.11 added the
#   /* Brackets should always be closed */  if (c != 0) { skip_upload = 1; }
# guard. No official php:* Docker image ships a build older than 5.3.29, so
# the interpreter is compiled here, pinned by version and SHA-256.
# ---------------------------------------------------------------------------
FROM debian:bookworm-20250929-slim AS php53

ARG PHP_VERSION=5.3.10
ARG PHP_SHA256=ee26ff003eaeaefb649735980d9ef1ffad3ea8c2836e6ad520de598da225eaab

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN curl -fsSL -o php.tar.gz "https://museum.php.net/php5/php-${PHP_VERSION}.tar.gz" \
 && echo "${PHP_SHA256}  php.tar.gz" | sha256sum -c - \
 && tar -xzf php.tar.gz \
 && rm php.tar.gz

WORKDIR /usr/src/php-5.3.10
# -fcommon and -std=gnu89 keep a 2012 codebase happy on GCC 12.
RUN CFLAGS="-fcommon -O1 -w -std=gnu89" ./configure \
        --prefix=/opt/php53 \
        --disable-all --disable-cli --enable-cgi \
        --without-pear --without-iconv \
        --disable-libxml --disable-dom --disable-simplexml \
        --disable-xml --disable-xmlreader --disable-xmlwriter \
        --disable-phar --disable-json --disable-pdo --without-sqlite3 \
 && make -j"$(nproc)" \
 && make install

# ---------------------------------------------------------------------------
# Stage 2 - Apache 2.4 serving PixelDrop through the PHP 5.3.10 CGI binary.
# ---------------------------------------------------------------------------
FROM debian:bookworm-20250929-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends apache2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=php53 /opt/php53/bin/php-cgi /usr/lib/php53-cgi/php-cgi
COPY php.ini /opt/php53/lib/php.ini
COPY apache-php53.conf /etc/apache2/conf-available/php53.conf
COPY 000-default.conf /etc/apache2/sites-available/000-default.conf

RUN a2enmod actions cgid rewrite \
 && a2enconf php53 \
 && rm -f /var/www/html/index.html

COPY src/ /var/www/html/
COPY flag.txt /flag.txt

RUN mkdir -p /var/www/html/uploads \
 && chown -R www-data:www-data /var/www/html/uploads \
 && chmod 0755 /var/www/html/uploads \
 && chmod 0444 /flag.txt \
 && printf 'ServerName pixeldrop.local\n' > /etc/apache2/conf-available/servername.conf \
 && a2enconf servername

EXPOSE 80
CMD ["apache2ctl", "-D", "FOREGROUND"]
