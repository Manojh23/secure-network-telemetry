.PHONY: test check build dev
test:
	go test -race -cover ./...
check:
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"
	python3 -m py_compile scripts/*.py
build:
	CGO_ENABLED=0 go build -trimpath -o dist/gateway ./cmd/gateway
dev:
	python3 scripts/dev_setup.py
	go run ./cmd/gateway
