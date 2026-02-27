APP_NAME=gcpsec

.PHONY: build test run-scan lint

build:
	go build -o bin/$(APP_NAME) ./cmd/$(APP_NAME)

test:
	go test ./...

run-scan: build
	./bin/$(APP_NAME) scan --repo . --out .gcpsec/scan.json
