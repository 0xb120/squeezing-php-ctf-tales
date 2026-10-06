# ---------------------------------------------------------------------------
# Stage 1 - build PHP 5.3.9 from source.
#
# 5.3.9 (10 Jan 2012) is the release that introduced `max_input_vars` as the
# fix for the 28C3 hash-collision DoS (CVE-2011-4885) - and the only release
# that shipped the broken version of that check (CVE-2012-0830). 5.3.10
# (02 Feb 2012) fixed it, which is why lab 01 pins 5.3.10 and this one does
# not. No official php:* image goes back further than 5.3.29, so the
# interpreter is compiled here, pinned by version and SHA-256.
# ---------------------------------------------------------------------------
FROM debian:bookworm-20250929-slim AS php539

ARG PHP_VERSION=5.3.9
ARG PHP_SHA256=424c6312ab23d1f8b0135cd52c2c08054d1ee9b21691e5ca3ebb0775670b7aee

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN curl -fsSL -o php.tar.gz "https://museum.php.net/php5/php-${PHP_VERSION}.tar.gz" \
 && echo "${PHP_SHA256}  php.tar.gz" | sha256sum -c - \
 && tar -xzf php.tar.gz \
 && rm php.tar.gz

WORKDIR /usr/src/php-5.3.9
# -fcommon and -std=gnu89 keep a 2012 codebase happy on GCC 12.
RUN CFLAGS="-fcommon -O1 -w -std=gnu89 -g" ./configure \
        --prefix=/opt/php53 \
        --disable-all --disable-cli --enable-cgi \
        --without-pear --without-iconv \
        --disable-libxml --disable-dom --disable-simplexml \
        --disable-xml --disable-xmlreader --disable-xmlwriter \
        --disable-phar --disable-json --disable-pdo --without-sqlite3 \
 && make -j"$(nproc)" \
 && make install

# ---------------------------------------------------------------------------
# Stage 2 - Apache 2.4 serving Sticky through the PHP 5.3.9 CGI binary.
# ---------------------------------------------------------------------------
FROM debian:bookworm-20250929-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends apache2 ca-certificates util-linux \
 && rm -rf /var/lib/apt/lists/*

COPY --from=php539 /opt/php53/bin/php-cgi /usr/lib/php53-cgi/php-cgi
COPY php.ini /opt/php53/lib/php.ini
COPY apache-php53.conf /etc/apache2/conf-available/php53.conf
COPY 000-default.conf /etc/apache2/sites-available/000-default.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN a2enmod actions cgid rewrite \
 && a2enconf php53 \
 && rm -f /var/www/html/index.html \
 && chmod 0755 /usr/local/bin/entrypoint.sh

COPY src/ /var/www/html/
COPY flag.txt /flag.txt

RUN chmod 0444 /flag.txt \
 && chmod -R 0444 /var/www/html \
 && chmod 0555 /var/www/html \
 && printf 'ServerName sticky.local\n' > /etc/apache2/conf-available/servername.conf \
 && a2enconf servername

EXPOSE 80
CMD ["/usr/local/bin/entrypoint.sh"]
