APP=signature-service
BASE ?= http://127.0.0.1:8080/v1
SHELL := /bin/bash

.PHONY: build run test run-test run-smoke-test cover clean setup smoke-curl smoke-curl-nojq

build:
	go build -o bin/$(APP) ./cmd/signature-service

run:
	@go run ./cmd/signature-service -mode='http' || [ $$? -eq 130 ]

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

setup:
	@set -e; \
	if ! command -v jq >/dev/null 2>&1; then \
	  echo "jq not found → attempting to install..."; \
	  if command -v brew >/dev/null 2>&1; then brew install jq; \
	  elif command -v apt-get >/dev/null 2>&1; then sudo apt-get update && sudo apt-get install -y jq; \
	  elif command -v dnf >/dev/null 2>&1; then sudo dnf install -y jq; \
	  elif command -v pacman >/dev/null 2>&1; then sudo pacman -Sy --noconfirm jq; \
	  elif command -v apk >/dev/null 2>&1; then sudo apk add --no-cache jq; \
	  else echo "Please install jq manually: https://jqlang.github.io/jq/"; fi; \
	else echo "jq OK"; fi; \
	if command -v openssl >/dev/null 2>&1; then echo "openssl OK"; else echo "openssl missing (optional, for signature verification)"; fi; \
	go version

smoke-curl:
	@set -euo pipefail; \
	echo "BASE=$(BASE)"; \
	echo "1) Health"; curl -sS "$(BASE)/health" | jq .; echo; \
	echo "2) Create dev-1"; curl -sS -H "Content-Type: application/json" -d '{"id":"dev-1","algorithm":"RSA","label":"L"}' "$(BASE)/devices" | jq .; echo; \
	echo "3) Sign hello"; SIGN1_JSON=$$(curl -sS -H "Content-Type: application/json" -d '{"data":"hello"}' "$(BASE)/devices/dev-1/sign"); echo $$SIGN1_JSON; \
	SIG1=$$(echo $$SIGN1_JSON | jq -r .signature); \
	SIGNED1=$$(echo $$SIGN1_JSON | jq -r .signed_data); \
	echo "4) Get device & confirm last_signature == SIG1"; \
	curl -sS "$(BASE)/devices/dev-1" \
	| jq --arg SIG1 "$$SIG1" '{id,algorithm,label,signature_counter,last_signature_base64, ok:(.last_signature_base64 == $$SIG1)}'; echo; \
	echo "5) Sign world"; curl -sS -H "Content-Type: application/json" -d '{"data":"world"}' "$(BASE)/devices/dev-1/sign" | tee /dev/stderr >/dev/null; echo; \
	echo "6) List devices"; curl -sS "$(BASE)/devices" | jq '.'

smoke-curl-nojq:
	@set -euo pipefail; \
	echo "BASE=$(BASE)"; \
	echo "1) Health"; curl -sS "$(BASE)/health"; echo; \
	echo "2) Create dev-1"; curl -sS -H "Content-Type: application/json" -d '{"id":"dev-1","algorithm":"RSA","label":"L"}' "$(BASE)/devices"; echo; \
	echo "3) Sign hello"; SIGN1_JSON=$$(curl -sS -H "Content-Type: application/json" -d '{"data":"hello"}' "$(BASE)/devices/dev-1/sign"); echo $$SIGN1_JSON; \
	SIG1=$$(printf "%s" "$$SIGN1_JSON" | sed -n 's/.*"signature":"\([^"]*\)".*/\1/p'); \
	SIGNED1=$$(printf "%s" "$$SIGN1_JSON" | sed -n 's/.*"signed_data":"\([^"]*\)".*/\1/p'); \
	echo "SIG1=$$SIG1"; echo "SIGNED1=$$SIGNED1"; \
	echo "4) Get device"; DEV1_JSON=$$(curl -sS "$(BASE)/devices/dev-1"); echo $$DEV1_JSON; \
	LAST=$$(printf "%s" "$$DEV1_JSON" | sed -n 's/.*"last_signature_base64":"\([^"]*\)".*/\1/p'); \
	if [ "$$LAST" = "$$SIG1" ]; then echo "OK: last_signature matches SIG1"; else echo "MISMATCH: last_signature != SIG1" && exit 1; fi; \
	echo "5) Sign world"; curl -sS -H "Content-Type: application/json" -d '{"data":"world"}' "$(BASE)/devices/dev-1/sign"; echo; \
	echo "6) List devices"; curl -sS "$(BASE)/devices"