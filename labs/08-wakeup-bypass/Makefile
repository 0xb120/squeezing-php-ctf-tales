COMPOSE = docker compose

.PHONY: up down solve solve-legacy verify logs shell shell-legacy clean

up:      ## build + start both services (8008 = modern, 9008 = legacy)
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down -v --remove-orphans

solve:
	$(COMPOSE) --profile solve run --rm --quiet-pull solver

solve-legacy:
	$(COMPOSE) --profile solve run --rm --quiet-pull solver \
	    python solve_legacy.py http://legacy http://challenge

verify:
	./verify.sh

logs:
	$(COMPOSE) logs -f

shell:
	$(COMPOSE) exec challenge bash

shell-legacy:
	$(COMPOSE) exec legacy bash

clean: down
