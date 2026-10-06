# A real, current, fully patched php-cgi: Debian bookworm ships 8.2.x with both
# the CVE-2012-1823 guard and the CVE-2024-4577 hardening compiled in.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      php8.2-cgi python3 \
 && rm -rf /var/lib/apt/lists/*

COPY src/ /var/www/html/
COPY gateway/cgi_gateway.py /opt/cgi_gateway.py
COPY flag.txt /flag.txt

RUN chown root:www-data /flag.txt && chmod 0440 /flag.txt \
 && chown -R root:root /var/www/html && chmod -R a=rX /var/www/html

ENV PHP_CGI=/usr/bin/php-cgi DOCROOT=/var/www/html PORT=80
EXPOSE 80
CMD ["python3", "/opt/cgi_gateway.py"]
