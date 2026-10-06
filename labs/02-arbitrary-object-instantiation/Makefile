LAB  := 02-arbitrary-object-instantiation
PORT := 8002

.PHONY: up down solve verify logs shell clean build

build:
	docker compose build

up: build
	docker compose up -d
	@echo "challenge is on http://127.0.0.1:$(PORT)/"

down:
	docker compose down -v --remove-orphans

solve:
	docker compose --profile solve run --rm --quiet-pull solver

verify:
	./verify.sh

logs:
	docker compose logs -f challenge registry

shell:
	docker compose exec challenge bash

clean: down
	docker image rm -f phpctf/$(LAB):php7.4.33 phpctf/$(LAB)-registry:1.4 2>/dev/null || true
