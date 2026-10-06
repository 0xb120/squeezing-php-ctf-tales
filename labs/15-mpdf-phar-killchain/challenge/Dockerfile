# ---------------------------------------------------------------------------
# stage 1 - resolve the vulnerable dependency set with composer
# ---------------------------------------------------------------------------
FROM composer:2 AS vendor

WORKDIR /build
COPY composer.json composer.lock ./

# mpdf/mpdf 8.0.10        -> vulnerable to the ORIG_SRC stream-wrapper bypass
# illuminate/* 8.83.27    -> real Laravel classes used by the PHPGGC Laravel/RCE6 chain
RUN composer install --no-interaction --no-progress --no-dev --prefer-dist --optimize-autoloader \
 && find vendor/mpdf/mpdf/ttfonts -type f ! -name 'DejaVu*' -delete \
 && rm -rf vendor/*/*/tests vendor/*/*/Tests vendor/*/*/.github vendor/*/*/docs

# ---------------------------------------------------------------------------
# stage 2 - the service
# ---------------------------------------------------------------------------
FROM php:7.4.33-apache

# NOTE: ext-gd is deliberately NOT built into this image.
# mpdf/mpdf declares ext-gd in composer.json (composer's `config.platform`
# satisfies the requirement so the lock file resolves), but none of the code
# paths exercised by this lab touch it: CSS data URIs are only base64-decoded
# and written to disk, and the "images" referenced through phar:// never pass
# mPDF's image-type guesser. Building gd here would mean pulling -dev packages
# from Debian bullseye, whose security pool no longer serves them, which would
# make this lab impossible to rebuild later.

# vendor/ must NOT be web-reachable: the whole point is that mPDF's cache
# directory cannot simply be listed over HTTP.
RUN sed -ri 's!/var/www/html!/var/www/app/public!g' \
        /etc/apache2/sites-available/*.conf /etc/apache2/apache2.conf \
 && rm -rf /var/www/html

RUN { \
      echo 'display_errors = On'; \
      echo 'error_reporting = E_ALL & ~E_DEPRECATED & ~E_NOTICE'; \
      echo 'memory_limit = 256M'; \
      echo 'post_max_size = 16M'; \
      echo 'max_execution_time = 60'; \
      echo 'expose_php = Off'; \
    } > /usr/local/etc/php/conf.d/zz-quotebuilder.ini

WORKDIR /var/www/app
COPY --from=vendor /build/vendor ./vendor
COPY composer.json composer.lock ./
COPY src/ ./

# mPDF's stock temp directory (vendor/mpdf/mpdf/tmp) has to be writable.
RUN mkdir -p vendor/mpdf/mpdf/tmp/mpdf \
 && chown -R www-data:www-data vendor/mpdf/mpdf/tmp

# The flag is root-only. www-data can never read it directly - not through the
# web root, not through an arbitrary-file-read primitive. Only code execution
# plus the setuid helper gets it out.
COPY flag.txt /flag.txt
RUN chown root:root /flag.txt && chmod 0400 /flag.txt \
 && cp /bin/cat /usr/local/bin/readflag \
 && chown root:root /usr/local/bin/readflag \
 && chmod 4755 /usr/local/bin/readflag

EXPOSE 80
