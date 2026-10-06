# The Art of PHP — CTF labs
LABS := $(sort $(notdir $(wildcard labs/*)))

.PHONY: help list verify clean
help:
	@echo "make list            list every lab"
	@echo "make verify          build+run+exploit+teardown every lab (slow)"
	@echo "make verify-NN       verify a single lab, e.g. make verify-12"
	@echo "make clean           remove stopped lab containers/volumes and logs"
	@echo ""
	@echo "Per lab:  cd labs/<lab> && make up | solve | verify | logs | down"

list:
	@for l in $(LABS); do \
	  port=$$(echo $$l | sed -E 's/^0*([0-9]+)-.*/\1/'); \
	  printf '  %-40s http://127.0.0.1:80%02d\n' "$$l" "$$port"; \
	done

verify:
	@scripts/verify-all.sh

verify-%:
	@scripts/verify-all.sh $*

clean:
	@rm -rf .verify-logs
	@for l in $(wildcard labs/*); do \
	  [ -f $$l/docker-compose.yml ] && (cd $$l && docker compose down -v --remove-orphans >/dev/null 2>&1 || true); \
	done; echo "clean"
