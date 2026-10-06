# A real headless browser: Chromium 124 on Alpine.
FROM zenika/alpine-chrome:124

USER root
RUN apk add --no-cache python3=3.11.14-r0 || apk add --no-cache python3

COPY bot.py /opt/bot.py
COPY flag.txt /flag.txt
RUN chmod 0444 /flag.txt && mkdir -p /tmp/chrome-profile && chown -R chrome:chrome /tmp/chrome-profile

USER chrome
ENV CHROME_BIN=/usr/bin/chromium-browser
EXPOSE 8080
ENTRYPOINT ["python3", "-u", "/opt/bot.py"]
