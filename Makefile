OUT ?= dist

.PHONY: test check fmt-check doctor setup-vmlinux workbench build-example build-examples clang-smoke

test:
	go test ./...

check:
	go test ./...
	go run ./cmd/hzn fmt ./examples -check

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
	go run ./cmd/hzn build ./examples/cgroupconnect -o $(OUT)
	go run ./cmd/hzn build ./examples/execwatch -o $(OUT)
	go run ./cmd/hzn build ./examples/execcount -o $(OUT)
	go run ./cmd/hzn build ./examples/lsmfile -o $(OUT)
	go run ./cmd/hzn build ./examples/openwatch -o $(OUT)
	go run ./cmd/hzn build ./examples/tcpconnect -o $(OUT)
	go run ./cmd/hzn build ./examples/tcpass -o $(OUT)
	go run ./cmd/hzn build ./examples/xdpdrop -o $(OUT)

clang-smoke:
	go test ./cmd/hzn -tags clang_smoke
