FROM php:8.1.34-apache

# The whole challenge:  <?php file($_POST[0]);
COPY src/ /var/www/html/
COPY flag.txt /flag.txt
RUN chmod 444 /flag.txt

# php.ini-production is what the original DownUnderCTF 2022 "minimal-php"
# challenge shipped.  The only thing that matters for this lab is that
# memory_limit is *finite*: it is the side channel.
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
 && { \
      echo 'memory_limit=128M'; \
      echo 'display_errors=Off'; \
      echo 'log_errors=Off'; \
      echo 'post_max_size=8M'; \
    } > "$PHP_INI_DIR/conf.d/zz-lab.ini"

# a few extra workers so the solver can use threads
RUN sed -i 's/^\(\s*\)MaxRequestWorkers.*/\1MaxRequestWorkers 16/' \
      /etc/apache2/mods-available/mpm_prefork.conf || true

# NB: a request with no POST parameter 0 makes file() throw a ValueError, so
# the health check has to send a real (harmless) stream URL.
HEALTHCHECK --interval=2s --timeout=3s --retries=45 \
  CMD php -r '$o=["http"=>["method"=>"POST","header"=>"Content-Type: application/x-www-form-urlencoded","content"=>"0=/etc/hostname"]]; exit(@file_get_contents("http://127.0.0.1/",false,stream_context_create($o))===""?0:1);'
