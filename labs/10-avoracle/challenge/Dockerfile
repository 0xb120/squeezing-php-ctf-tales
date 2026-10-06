FROM php:8.2.29-apache

# The session directory is a volume shared with the "Defender" service, so
# both containers can see (and one of them can delete) the session files.
RUN set -eux; \
    mkdir -p /sessions; \
    chmod 0777 /sessions; \
    printf '%s\n' \
      'session.save_path = "/sessions"' \
      'session.use_strict_mode = 0' \
      'session.gc_probability = 0' \
      'expose_php = Off' \
      > /usr/local/etc/php/conf.d/zz-inkstone.ini

COPY src/ /var/www/html/
RUN printf 'PHRACK{defender_ate_my_session}\n' > /flag.txt; \
    chmod 0644 /flag.txt
