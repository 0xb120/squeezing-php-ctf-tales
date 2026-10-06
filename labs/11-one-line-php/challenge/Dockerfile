# The original HITCON CTF 2018 "One Line PHP Challenge" ran on a stock
# Ubuntu 18.04 + Apache + PHP 7.2 box.  php:7.2.34-apache is the last 7.2
# release and is the closest reproducible equivalent.
FROM php:7.2.34-apache

# ---------------------------------------------------------------------------
# php.ini.  Written out explicitly so that the challenge is reproducible and
# so that players can read exactly what they are up against (the original
# challenge also published its configuration; README.md reproduces this block
# verbatim).  See WRITEUP.md for why each one matters.
#
# Provenance of every value, measured against php:7.2.34-cli with no ini file
# and against the php.ini-production that ships in the same image:
#   * upload_max_filesize=2M, post_max_size=8M, max_execution_time=30,
#     file_uploads=On, allow_url_fopen=On, allow_url_include=Off and every
#     session.* line below are PHP 7.2's own defaults (compiled-in, and
#     identical to php.ini-production).  The session.upload_progress.* block
#     is commented out in php.ini-production precisely because the values
#     printed there are already the built-in defaults.
#   * session.save_path=/var/lib/php/sessions is the Debian/Ubuntu *package*
#     default (upstream leaves it empty, i.e. /tmp).  On Debian that directory
#     really is 1733 root:root, which is why it cannot be listed.
#   * expose_php=Off is the one deliberate deviation (upstream default is On).
#     It hides nothing that matters; it only keeps the banner out of headers.
# The technique does NOT need a raised post_max_size: the exploit announces a
# Content-Length below the stock 8M and then delivers a fraction of it.
# ---------------------------------------------------------------------------
RUN set -eux; \
    mkdir -p /var/lib/php/sessions; \
    chown root:root /var/lib/php/sessions; \
    chmod 1733 /var/lib/php/sessions; \
    { \
      echo 'allow_url_fopen = On'; \
      echo 'allow_url_include = Off'; \
      echo 'file_uploads = On'; \
      echo 'upload_max_filesize = 2M'; \
      echo 'post_max_size = 8M'; \
      echo 'max_execution_time = 30'; \
      echo 'session.save_path = "/var/lib/php/sessions"'; \
      echo 'session.auto_start = Off'; \
      echo 'session.serialize_handler = php'; \
      echo 'session.use_strict_mode = 0'; \
      echo 'session.upload_progress.enabled = On'; \
      echo 'session.upload_progress.cleanup = On'; \
      echo 'session.upload_progress.prefix = "upload_progress_"'; \
      echo 'session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"'; \
      echo 'session.upload_progress.freq = "1%"'; \
      echo 'session.upload_progress.min_freq = "1"'; \
      echo 'expose_php = Off'; \
    } > /usr/local/etc/php/conf.d/zz-challenge.ini

COPY src/ /var/www/html/

# The flag is never printed by the challenge: the one-liner only ever
# highlight_file()s itself or include()s the path you give it.  Reading it
# therefore requires code execution.
RUN set -eux; \
    printf 'PHRACK{upload_progress_wrote_my_shell_for_me}\n' > /flag.txt; \
    chown root:www-data /flag.txt; \
    chmod 0640 /flag.txt
