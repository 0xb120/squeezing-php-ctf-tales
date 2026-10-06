COMPOSE = docker compose

.PHONY: up down solve verify logs shell clean

up:
	$(COMPOSE) up -d --build
	@echo "challenge: http://127.0.0.1:8017/index.php"

down:
	$(COMPOSE) down -v --remove-orphans

solve:
	$(COMPOSE) --profile solve run --rm --quiet-pull solver

verify:
	./verify.sh

logs:
	$(COMPOSE) logs -f

shell:
	$(COMPOSE) exec php bash

clean: down
	-docker image rm phpctf-17-nginx phpctf-17-fpm 2>/dev/null || true
