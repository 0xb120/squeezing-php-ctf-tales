LAB  := 13-filter-chain-oracle
PORT := 8013
DC   := docker compose

.PHONY: up down solve verify logs shell clean

up:            ## build + start the vulnerable service
	$(DC) up -d --build challenge
	@echo "challenge on http://127.0.0.1:$(PORT)/   (POST 0=<php stream url>)"

down:          ## stop everything
	$(DC) down -v --remove-orphans

solve:         ## run the exploit from a container
	$(DC) --profile solve run --rm --quiet-pull solver

verify:        ## full build -> exploit -> assert -> teardown
	./verify.sh

logs:
	$(DC) logs -f challenge

shell:
	$(DC) exec challenge bash

clean: down
	docker image rm -f phpctf-13-filter-chain-oracle-challenge 2>/dev/null || true
