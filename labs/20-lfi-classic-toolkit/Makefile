LAB    := 20-lfi-classic-toolkit
PORT   := 8020
LEGACY := 9020

.PHONY: up down solve verify logs shell clean

up:
	docker compose up -d --build challenge legacy
	@echo "modern wing: http://127.0.0.1:$(PORT)/"
	@echo "legacy wing: http://127.0.0.1:$(LEGACY)/        (php 5.3.3)"
	@echo "             http://127.0.0.1:$(LEGACY)/v534/   (php 5.3.4)"

down:
	docker compose down -v --remove-orphans

solve:
	docker compose --profile solve run --rm --quiet-pull solver

verify:
	./verify.sh

logs:
	docker compose logs -f challenge legacy

shell:
	docker compose exec challenge bash

clean: down
	docker image rm -f phpctf/$(LAB):php8.2.33 phpctf/$(LAB):php5.3.3 2>/dev/null || true
