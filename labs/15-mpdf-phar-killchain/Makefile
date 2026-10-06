COMPOSE := docker compose

.PHONY: up down solve verify logs shell clean

up:
	$(COMPOSE) up -d --build
	@echo "challenge:  http://127.0.0.1:8015/"

down:
	$(COMPOSE) down -v --remove-orphans

solve:
	$(COMPOSE) --profile solve run --rm --quiet-pull solver

verify:
	./verify.sh

logs:
	$(COMPOSE) logs -f challenge

shell:
	$(COMPOSE) exec challenge bash

clean: down
	-docker image rm phpctf-15-mpdf-phar-killchain:latest
