# php-src issue #10453 ("limit the number of filters in a php://filter chain")
# became the RFC "Limit maximum number of filter chains", accepted 30/0/2 and
# implemented in PHP 8.6: chains longer than 16 filters raise a deprecation in
# 8.6 and become an error in 8.7, and the cap is only adjustable through the
# filter.max_filter_count *stream context* option, not through php.ini.  This
# lab therefore pins 8.2.33 - the last 8.2 release - which happily accepts
# chains of several hundred converters, i.e. a version where the technique
# works exactly as published.  The image is Debian trixie, so iconv comes from
# glibc 2.41 and every charset the chain needs is present.
FROM php:8.2.33-apache

# ---------------------------------------------------------------------------
# Hardening: the whole point of the challenge is that none of this helps.
#   file_uploads=Off              no /tmp/phpXXXXXX temporary files
#   session.upload_progress=Off   no attacker-controlled session files
#   allow_url_include=Off         no RFI, no data:// include
#   allow_url_fopen=Off           no remote streams at all
# php:// is not a "URL" wrapper, so php://filter survives all of it.
# ---------------------------------------------------------------------------
RUN set -eux; \
    { \
      echo 'file_uploads = Off'; \
      echo 'allow_url_fopen = Off'; \
      echo 'allow_url_include = Off'; \
      echo 'session.upload_progress.enabled = Off'; \
      echo 'session.auto_start = Off'; \
      echo 'expose_php = Off'; \
      echo 'display_errors = On'; \
      echo 'error_reporting = E_ALL & ~E_WARNING & ~E_NOTICE & ~E_DEPRECATED'; \
    } > /usr/local/etc/php/conf.d/zz-challenge.ini

COPY src/ /var/www/html/
COPY readflag.c /tmp/readflag.c

RUN set -eux; \
    printf 'PHRACK{no_files_needed_iconv_wrote_the_webshell}\n' > /flag.txt; \
    chown root:root /flag.txt; \
    chmod 0400 /flag.txt; \
    gcc -O2 -static -o /readflag /tmp/readflag.c; \
    rm -f /tmp/readflag.c; \
    chown root:root /readflag; \
    chmod 4755 /readflag; \
    chown -R root:root /var/www/html; \
    chmod -R a-w /var/www/html; \
    chmod 0555 /tmp /var/tmp
