LAB  := 10-avoracle
PORT := 8010

.PHONY: up down solve solve-passive verify logs shell clean

up:
	docker compose up -d --build
	@echo "challenge:        http://127.0.0.1:$(PORT)/"
	@echo "defender console: http://127.0.0.1:9010/status"

down:
	docker compose down -v --remove-orphans

solve:
	docker compose --profile solve run --rm --quiet-pull solver

# Same exploit without poking the scanner's /scan endpoint: it waits for the
# real-time protection timer instead. Slower, closer to the real thing.
solve-passive:
	docker compose --profile solve run --rm --quiet-pull solver \
	    python solve.py http://challenge http://scanner:8080 --passive

verify:
	./verify.sh

logs:
	docker compose logs -f

shell:
	docker compose exec challenge bash

clean: down
	docker compose rm -fsv >/dev/null 2>&1 || true
