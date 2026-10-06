# Lab 03 - Format-String Oriented Programming (host port 8003)
COMPOSE = docker compose
URL     = http://127.0.0.1:8003/

.PHONY: up down solve verify logs shell clean

up:            ## build + start the vulnerable service
	$(COMPOSE) up -d --build challenge
	@echo "challenge up -> $(URL)?driver=NullDriver"

down:          ## stop and remove the service + volumes
	$(COMPOSE) down -v --remove-orphans

solve:         ## run the automated exploit against a running lab
	$(COMPOSE) --profile solve run --rm --quiet-pull solver

verify:        ## build -> up -> solve -> assert flag -> down
	./verify.sh

logs:          ## follow challenge logs
	$(COMPOSE) logs -f challenge

shell:         ## shell inside the challenge container
	$(COMPOSE) exec challenge sh

clean: down    ## alias for down
	@true
