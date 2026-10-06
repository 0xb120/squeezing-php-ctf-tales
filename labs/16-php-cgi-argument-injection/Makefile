COMPOSE = docker compose

.PHONY: up down solve verify logs shell clean

up:
	$(COMPOSE) up -d --build
	@echo "classic  : http://127.0.0.1:8016/"
	@echo "worstfit : http://127.0.0.1:9016/"

down:
	$(COMPOSE) down -v --remove-orphans

solve:
	$(COMPOSE) --profile solve run --rm --quiet-pull solver

verify:
	./verify.sh

logs:
	$(COMPOSE) logs -f

shell:
	$(COMPOSE) exec challenge bash

clean: down
	-docker image rm phpctf-16-php-cgi 2>/dev/null || true
