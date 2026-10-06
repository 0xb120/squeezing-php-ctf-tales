COMPOSE = docker compose

.PHONY: up down solve verify logs shell clean

up:      ## build + start the lab on http://127.0.0.1:8007/
	$(COMPOSE) up -d --build

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
