FROM python:3.12-alpine

COPY registry.py /srv/registry.py
COPY flag.txt /flag.txt

RUN mkdir -p /pkgcache \
 && chmod 0777 /pkgcache \
 && chmod 0400 /flag.txt

EXPOSE 8080
CMD ["python", "-u", "/srv/registry.py"]
