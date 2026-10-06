LAB  := 05-serialize-then-replace
PORT := 8005

.PHONY: up down solve verify logs shell clean

up:
	docker compose up -d --build
	@echo "challenge on http://127.0.0.1:$(PORT)/"

down:
	docker compose down -v --remove-orphans

solve:
	docker compose --profile solve run --rm --quiet-pull solver

verify:
	./verify.sh

logs:
	docker compose logs -f challenge

shell:
	docker compose exec challenge bash

clean: down
	-docker image rm phpctf/$(LAB):latest
