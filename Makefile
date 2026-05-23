.PHONY: test check doctor setup-vmlinux workbench build-example clang-smoke

test:
	go test ./...

check:
	go test ./...

doctor:
	go run ./cmd/hzn doctor

setup-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c | sudo tee /usr/local/include/vmlinux.h >/dev/null

workbench:
	go run ./cmd/hzn workbench ./examples/execwatch -o dist

build-example:
	go run ./cmd/hzn build ./examples/execwatch -o dist

clang-smoke:
	go test ./... -tags clang_smoke
