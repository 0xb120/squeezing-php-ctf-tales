#!/bin/sh
set -e
mkdir -p /run /var/log/nginx
php-fpm --fpm-config /usr/local/etc/php-fpm.conf
exec nginx -c /etc/nginx/nginx.conf
