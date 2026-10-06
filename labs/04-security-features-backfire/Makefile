# lab 04 - security features backfire
COMPOSE = docker compose

.PHONY: up down solve verify logs shell clean

up:
	$(COMPOSE) up -d --build
	@echo "challenge: http://127.0.0.1:8004/"
	@echo "admin bot: http://127.0.0.1:9004/  (POST /report url=...)"

down:
	$(COMPOSE) down -v --remove-orphans

solve:
	$(COMPOSE) --profile solve run --rm --use-aliases --quiet-pull solver

verify:
	./verify.sh

logs:
	$(COMPOSE) logs -f

shell:
	$(COMPOSE) exec challenge bash

clean: down
	docker image rm -f phpctf-04-challenge:latest phpctf-04-bot:latest 2>/dev/null || true
