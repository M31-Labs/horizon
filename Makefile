OUT ?= dist
HZN_EXAMPLES := \
	./examples/cgroupconnect \
	./examples/execwatch \
	./examples/execcount \
	./examples/lsmfile \
	./examples/openwatch \
	./examples/tcpconnect \
	./examples/tcpass \
	./examples/xdpdrop

.PHONY: test check ci ci-go ci-clang fmt-check doctor setup-vmlinux workbench build-example build-examples bindings-smoke clang-smoke

test:
	go test ./...

check:
	go test ./...
	go run ./cmd/hzn fmt ./examples -check

ci: ci-go ci-clang

ci-go: check bindings-smoke

ci-clang: build-examples clang-smoke

fmt-check:
	go run ./cmd/hzn fmt ./examples -check

doctor:
	go run ./cmd/hzn doctor

setup-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c | sudo tee /usr/local/include/vmlinux.h >/dev/null

workbench:
	go run ./cmd/hzn workbench ./examples/execwatch -o $(OUT)

build-example:
	go run ./cmd/hzn build ./examples/execwatch -o $(OUT)

build-examples:
	@for example in $(HZN_EXAMPLES); do \
		if [ "$${GITHUB_ACTIONS:-}" = "true" ]; then echo "::group::hzn build $$example"; fi; \
		echo "hzn build $$example"; \
		go run ./cmd/hzn build "$$example" -o "$(OUT)"; status=$$?; \
		if [ "$${GITHUB_ACTIONS:-}" = "true" ]; then echo "::endgroup::"; fi; \
		if [ $$status -ne 0 ]; then exit $$status; fi; \
	done

bindings-smoke:
	@tmp=".hzn-bindings-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp"; \
	trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	for example in $(HZN_EXAMPLES); do \
		if [ "$${GITHUB_ACTIONS:-}" = "true" ]; then echo "::group::hzn bindgen $$example"; fi; \
		rm -f "$$tmp"/*.go; \
		echo "hzn bindgen $$example"; \
		go run ./cmd/hzn bindgen "$$example" -o "$$tmp/bindings.go" && go test "./$$tmp"; status=$$?; \
		if [ "$${GITHUB_ACTIONS:-}" = "true" ]; then echo "::endgroup::"; fi; \
		if [ $$status -ne 0 ]; then exit $$status; fi; \
	done

clang-smoke:
	go test ./cmd/hzn -tags clang_smoke
