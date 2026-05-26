OUT ?= dist
HZN_EXAMPLES := \
	./examples/cgroupconnect \
	./examples/execwatch \
	./examples/execcount \
	./examples/execdeny \
	./examples/killwatch \
	./examples/lsmfile \
	./examples/openwatch \
	./examples/tcpconnect \
	./examples/tcpass \
	./examples/xdpdrop

.PHONY: test check ci ci-go ci-clang fmt-check doctor setup-vmlinux workbench build-example build-examples bindings-smoke clang-smoke golden-update verifier-fixtures-update kernel-smoke

test:
	@log="$$(mktemp)"; \
	if go test ./... >"$$log" 2>&1; then \
		echo "ok go test ./..."; \
		rm -f "$$log"; \
	else \
		cat "$$log"; \
		rm -f "$$log"; \
		exit 1; \
	fi

check: test fmt-check

ci: ci-go ci-clang

ci-go: check bindings-smoke

ci-clang: build-examples clang-smoke

fmt-check:
	@log="$$(mktemp)"; \
	if go run ./cmd/hzn fmt ./examples -check >"$$log" 2>&1; then \
		echo "ok hzn fmt ./examples -check"; \
		rm -f "$$log"; \
	else \
		cat "$$log"; \
		rm -f "$$log"; \
		exit 1; \
	fi

doctor:
	go run ./cmd/hzn doctor

setup-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c | sudo tee /usr/local/include/vmlinux.h >/dev/null

workbench:
	go run ./cmd/hzn workbench ./examples/execwatch -o $(OUT)

build-example:
	@log="$$(mktemp)"; \
	if go run ./cmd/hzn build ./examples/execwatch -o "$(OUT)" >"$$log" 2>&1; then \
		echo "ok hzn build ./examples/execwatch"; \
		rm -f "$$log"; \
	else \
		cat "$$log"; \
		rm -f "$$log"; \
		exit 1; \
	fi

build-examples:
	@for example in $(HZN_EXAMPLES); do \
		log="$$(mktemp)"; \
		if [ "$${GITHUB_ACTIONS:-}" = "true" ]; then echo "::group::hzn build $$example"; fi; \
		if go run ./cmd/hzn build "$$example" -o "$(OUT)" >"$$log" 2>&1; then \
			echo "ok hzn build $$example"; \
			rm -f "$$log"; \
			status=0; \
		else \
			status=$$?; \
			echo "failed hzn build $$example"; \
			cat "$$log"; \
			rm -f "$$log"; \
		fi; \
		if [ "$${GITHUB_ACTIONS:-}" = "true" ]; then echo "::endgroup::"; fi; \
		if [ $$status -ne 0 ]; then exit $$status; fi; \
	done

bindings-smoke:
	@tmp=".hzn-bindings-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp"; \
	trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	for example in $(HZN_EXAMPLES); do \
		log="$$tmp/$$(basename "$$example").log"; \
		if [ "$${GITHUB_ACTIONS:-}" = "true" ]; then echo "::group::hzn bindgen $$example"; fi; \
		rm -f "$$tmp"/*.go; \
		rm -f "$$log"; \
		if go run ./cmd/hzn bindgen "$$example" -o "$$tmp/bindings.go" >"$$log" 2>&1 && go test "./$$tmp" >>"$$log" 2>&1; then \
			echo "ok hzn bindgen $$example"; \
			status=0; \
		else \
			status=$$?; \
			echo "failed hzn bindgen $$example"; \
			cat "$$log"; \
		fi; \
		if [ "$${GITHUB_ACTIONS:-}" = "true" ]; then echo "::endgroup::"; fi; \
		if [ $$status -ne 0 ]; then exit $$status; fi; \
	done

golden-update:
	go test ./compiler -run TestGoldenExamplesWorkbench -update-golden -v

verifier-fixtures-update:
	go test ./verifier -run TestVerifierCatalogFixtures -update-fixtures -v

clang-smoke:
	@log="$$(mktemp)"; \
	if go test ./cmd/hzn -tags clang_smoke >"$$log" 2>&1; then \
		echo "ok go test ./cmd/hzn -tags clang_smoke"; \
		rm -f "$$log"; \
	else \
		cat "$$log"; \
		rm -f "$$log"; \
		exit 1; \
	fi

kernel-smoke:
	@if [ -z "$(KERNEL)" ]; then echo "usage: make kernel-smoke KERNEL=<5.10|5.15|6.1|6.6> OUT=<bpf-obj-dir>"; exit 2; fi
	bash scripts/kernel-matrix/run.sh $(KERNEL) $(OUT)
