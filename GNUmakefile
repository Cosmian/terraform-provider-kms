default: build

build:
	go build ./...

test:
	go test -v ./internal/...

testacc:
	TF_ACC=1 go test -v -timeout 120s ./internal/...

fmt:
	gofmt -s -w .

lint:
	golangci-lint run ./...

docs:
	go generate ./...

.PHONY: build test testacc fmt lint docs
