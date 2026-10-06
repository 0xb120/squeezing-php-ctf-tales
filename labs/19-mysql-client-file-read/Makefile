LAB  := 19-mysql-client-file-read
PORT := 8019
ROGUE := 9019

.PHONY: up down solve verify logs shell clean rogue

up:
	docker compose up -d --build challenge rogue
	@echo "panel      : http://127.0.0.1:$(PORT)/"
	@echo "rogue mysql: 127.0.0.1:$(ROGUE)  (point the panel at it)"

down:
	docker compose down -v --remove-orphans

solve:
	docker compose --profile solve run --rm --quiet-pull solver

verify:
	./verify.sh

# Run the rogue server on the host (needs Python 3 only) instead of in Docker.
rogue:
	python3 solve/rogue.py --bind 127.0.0.1:$(ROGUE) --file /flag.txt

logs:
	docker compose logs -f challenge rogue

shell:
	docker compose exec challenge bash

clean: down
	docker compose rm -fsv >/dev/null 2>&1 || true
