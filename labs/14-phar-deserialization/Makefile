LAB  := 14-phar-deserialization
PORT := 8014
DC   := docker compose

.PHONY: up down solve verify logs shell clean mitigations

up:            ## build + start the vulnerable service
	$(DC) up -d --build challenge
	@echo "challenge on http://127.0.0.1:$(PORT)/"

down:          ## stop everything
	$(DC) down -v --remove-orphans

solve:         ## run the exploit from a container
	$(DC) --profile solve run --rm --quiet-pull solver

verify:        ## full build -> exploit -> assert -> teardown
	./verify.sh

mitigations:   ## show PHP 8 / phar.readonly / stream_wrapper_unregister behaviour
	./mitigations.sh

logs:
	$(DC) logs -f challenge

shell:
	$(DC) exec challenge bash

clean: down
	docker image rm -f phpctf-14-phar-deserialization-challenge 2>/dev/null || true
