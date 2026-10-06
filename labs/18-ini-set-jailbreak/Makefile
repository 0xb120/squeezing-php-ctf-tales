LAB  := 18-ini-set-jailbreak
PORT := 8018

.PHONY: up down solve verify logs shell clean preload rce

up:
	docker compose up -d --build
	@echo "playground: http://127.0.0.1:$(PORT)/"

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

# Build the LD_PRELOAD payload used by the optional stage-2 RCE.
preload:
	docker run --rm -v "$(CURDIR)/solve:/w" -w /w debian:trixie-slim sh -c \
	  'apt-get update -qq >/dev/null && apt-get install -y -qq gcc libc6-dev >/dev/null && \
	   gcc -shared -fPIC -o hook.so hook.c && chmod 644 hook.so'
	@ls -l solve/hook.so

# Stage 1 + stage 2 (needs `make preload` first).
rce:
	docker compose --profile solve run --rm --quiet-pull solver python solve.py http://challenge --rce

clean: down
	rm -f solve/hook.so
	docker compose rm -fsv >/dev/null 2>&1 || true
