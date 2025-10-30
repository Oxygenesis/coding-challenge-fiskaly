APP=signature-service

.PHONY: build run test run-test run-smoke-test cover clean

build:
	go build -o bin/$(APP) ./cmd/signature-service

run:
	@go run ./cmd/signature-service || [ $$? -eq 130 ]

test:
	go test ./... -cover -coverprofile=coverage.out -covermode=atomic

run-test: test
	@echo "Coverage:"
	@go tool cover -func=coverage.out | tail -n 1

run-httpapi-test:
	go test ./internal/httpapi -run TestHTTPHandlers -v

cover:
	go tool cover -html=coverage.out -o coverage.html
	@echo "Open coverage.html"

clean:
	rm -rf bin coverage.out coverage.html

run-smoke-test:
	go run -tags=smokebin ./smoke-test