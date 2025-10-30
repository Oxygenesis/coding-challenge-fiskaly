# Signature Service Go

This project follows a Clean Architecture structure inspired by Domain-Driven Design (DDD) principles - Production ready based on previous project.

The domain layer defines core entities (SignatureDevice) and interfaces (Signer, Repository) that capture the essential business rules.
The application (service) layer orchestrates these domain operations as use cases.
Infrastructure layers (http, storage, crypto) implement the interfaces, keeping external concerns decoupled from core logic.

This design enables easy extension (e.g., adding new signing algorithms or persistence backends) without changing the domain logic, while ensuring testability and clear separation of concerns.

It exposes REST endpoints to create **signature devices** and sign arbitrary data using **RSA** or **ECDSA**, with a strictly monotonically increasing, gap-free `signature_counter` and signature chaining.

---

## Table of Contents
- [Objectives ↔ Implementation Map](#objectives--implementation-map)
- [Addressed TODOs (from starter comments)](#addressed-todos-from-starter-comments)
- [Project Layout](#project-layout)
- [Core Domain & Logic](#core-domain--logic)
- [HTTP API](#http-api)
- [Run, Test, Coverage, Smoke](#run-test-coverage-smoke)
- [cURL Playbook (one-by-one)](#curl-playbook-one-by-one)
- [Cryptographic Verification (optional)](#cryptographic-verification-optional)
- [Concurrency & Correctness](#concurrency--correctness)
- [Extensibility](#extensibility)
- [Configuration](#configuration)
- [AI Tools Disclosure](#ai-tools-disclosure)
- [Future Work](#future-work)

---

## Objectives ↔ Implementation Map

| Challenge Objective | Where Implemented | Notes |
|---|---|---|
| Create signature devices (with algorithm + generated keypair) | `internal/service/device_service.go` (+ crypto signers, storage) | Service validates algorithm, generates keypair via factory, persists device. |
| Sign data with device; **secured string** `<counter>_<data>_<last_b64>` | `internal/service/device_service.go: Sign` | Handles base case `counter==0` → `last = base64(deviceID)`. |
| Return `{ "signature": base64(signature), "signed_data": "..." }` | `internal/app/http/handler/device.go: Sign` | Pure HTTP envelope; service returns typed response. |
| Monotonic, gap-free `signature_counter` | `internal/storage/memory_store.go: Update` | Atomic update under mutex; counter increment happens inside single critical section used for signing. |
| Multiple devices, per-device isolation | Storage keyed by `device.ID` | No user management needed per challenge. |
| Algorithm plug-ability (RSA, ECDSA now; easy to extend) | `internal/domain/signer.go`, `internal/crypto/*_signer.go` | Service depends on `domain.Signer`; factories produce concrete signers. |
| RESTful HTTP API | `internal/app/http/http.go`, handlers under `internal/app/http/handler` | Standard library `net/http` + `ServeMux`, clean routing. |
| List/retrieve operations | `GET /v1/devices`, `GET /v1/devices/{id}` | See [HTTP API](#http-api). |
| Verifiable correctness via tests | `internal/**/**_test.go`, `cmd/signature-service/main_test.go` | Unit + HTTP contract tests + smoke runner. |

---

## Addressed TODOs (from starter comments)

> Original TODO comments and where they are fulfilled:

- `// TODO: REST endpoints ...`  
  **Implemented in** `internal/app/http/http.go` (router) and `internal/app/http/handler/device.go` (handlers).

- `// TODO: register further HandlerFuncs here ...`  
  **Implemented in** `internal/app/http/http.go` → mounts `GET /v1/health`, `POST/GET /v1/devices`, `GET /v1/devices/{id}`, `POST /v1/devices/{id}/sign`.

- `// TODO: implement RSA and ECDSA signing ...`  
  **Implemented in** `internal/crypto/rsa_signer.go` and `internal/crypto/ecdsa_signer.go`. Both satisfy `domain.Signer`.

- `// TODO: signature device domain model ...`  
  **Implemented in** `internal/domain/device.go` (entity, invariants like `InitialLastSignature`).

- `// TODO: in-memory persistence ...`  
  **Implemented in** `internal/storage/memory_store.go` (concurrency-safe repo with `Update` closure to keep sign+increment atomic).

- `// TODO: add further configuration parameters here ...`  
  **Provided via** `cmd/signature-service/main.go` flags (`-mode`, `-addr`, `-t`) and `internal/app/http/Start(ctx, addr, svc, test)` signature to add more config in one place.

---

## Project Layout

```text
cmd/signature-service/
  main.go                 # CLI entry; wires repo + service + http.Start
  main_test.go            # Covers ok+error+unsupported-mode + crypto factory

internal/
  app/http/
    http.go               # Start() + router wiring (std net/http)
    handler/
      device.go           # Health, Create, List, Get, Sign
      device_test.go      # Handler-level contract tests
    middleware/
      recovery.go         # Panic recovery to 500
      recovery_test.go
  crypto/
    rsa_signer.go         # RSA SHA-256 PKCS#1v1.5
    ecdsa_signer.go       # ECDSA SHA-256 (ASN.1)
    *_test.go
  domain/
    device.go             # SignatureDevice, InitialLastSignature()
    signer.go             # Signer interface
    *_test.go
  service/
    device_service.go     # Business logic: create/sign/list/get
    device_service_test.go
  storage/
    memory_store.go       # Concurrency-safe in-memory repository
    memory_store_test.go

pkg/id/
  generator.go            # UUIDv4 wrapper (mockable)
  generator_test.go

smoke-test/
  main.go                 # In-process HTTP smoke (build tag: smokebin)

Makefile
go.mod
README.md
```

---

## Core Domain & Logic

**Entity:** `SignatureDevice`
- `id` (string), `algorithm` (`"RSA"` or `"ECC"`), `label` (string),  
  `signature_counter` (uint64), `last_signature_base64` (string), `public_key_pem` (string).

**Sign flow (`service.Sign`)**
1. Load device + signer.
2. Compute `last`:
   - If `counter == 0`: `last = base64(id)`.
   - Else use `device.last_signature_base64`.
3. Build `secured_data`: `"<counter>_<data>_<last>"`.
4. Sign `secured_data` with device `signer` → raw signature bytes.
5. Encode signature to base64, return response.
6. **Atomically update** device in repository:
   - Set `last_signature_base64 = signatureB64`
   - Increment `signature_counter++`

All steps happen inside repo `Update` critical section to ensure **no gaps** and strict monotonicity.

---

## HTTP API

**Base path:** `/v1`

### Health
```http
GET /v1/health
→ 200 {"status":"ok"}
```

### Create device
```http
POST /v1/devices
Body: {"id":"<string>", "algorithm":"RSA|ECC", "label":"<optional>"}
→ 201 {id, algorithm, label, signature_counter, last_signature_base64, public_key_pem}
Errors:
- 400 invalid json / invalid algorithm / missing id
- 409 id already exists
- 500 storage error
```

### List devices
```http
GET /v1/devices
→ 200 [ ...devices... ]
- 500 on storage error
```

### Get device
```http
GET /v1/devices/{id}
→ 200 device JSON
- 404 if not found
- 500 on storage error
```

### Sign
```http
POST /v1/devices/{id}/sign
Body: {"data":"<string>"}
→ 200 {"signature":"<base64>", "signed_data":"<counter>_<data>_<last_b64>"}
Errors:
- 400 invalid json / empty data
- 404 device not found
- 500 on internal/storage error
```

---

## Run, Test, Coverage, Smoke

### Prerequisites
- Go **1.20+**
- `jq` (for cURL examples)
- `openssl` (optional, for signature verification)

### Make targets

```bash
# Build the binary
make build

# Run the HTTP server (listens on :8080)
make run

# Unit tests (with coverage)
make test

# Only run unit tests (alias)
make run-test

# Run smoke (in-process server; prints requests/responses)
make run-smoke-test
```

> `make run-smoke-test` uses a build tag (`smokebin`) to exclude the smoke from unit coverage.

### Manual run

```bash
go run ./cmd/signature-service -mode=http -addr=:8080
```

### Coverage report

```bash
go test ./... -cover -coverprofile=coverage.out -covermode=atomic
go tool cover -func=coverage.out
```

---

## cURL Playbook (one-by-one)

```bash
BASE="http://127.0.0.1:8080/v1"

# 1) Health
curl -sS "$BASE/health"

# 2) Create RSA device dev-1
curl -sS -H "Content-Type: application/json"   -d '{"id":"dev-1","algorithm":"RSA","label":"L"}'   "$BASE/devices"

# 3) Sign "hello" (capture)
SIGN1_JSON=$(curl -sS -H "Content-Type: application/json"   -d '{"data":"hello"}' "$BASE/devices/dev-1/sign"); echo "$SIGN1_JSON"

# 4) Extract signature + signed_data
SIG1=$(echo "$SIGN1_JSON" | jq -r '.signature')
SIGNED1=$(echo "$SIGN1_JSON" | jq -r '.signed_data')
echo "$SIG1"; echo "$SIGNED1"

# 5) Get device and confirm last_signature == SIG1
curl -sS "$BASE/devices/dev-1" | jq --arg SIG1 "$SIG1" '{id,algorithm,label,signature_counter,last_signature_base64,public_key_pem, ok:(.last_signature_base64 == $SIG1)}'

# 6) Sign "world"
SIGN2_JSON=$(curl -sS -H "Content-Type: application/json"   -d '{"data":"world"}' "$BASE/devices/dev-1/sign"); echo "$SIGN2_JSON"
SIG2=$(echo "$SIGN2_JSON" | jq -r '.signature')
SIGNED2=$(echo "$SIGN2_JSON" | jq -r '.signed_data')

# 7) List devices
curl -sS "$BASE/devices" | jq '.'

# 8) Create ECC device dev-2
curl -sS -H "Content-Type: application/json"   -d '{"id":"dev-2","algorithm":"ECC","label":"E"}'   "$BASE/devices"

# Negative cases
# 9) Invalid algorithm → 400
curl -sS -o /dev/null -w "%{http_code}
"   -H "Content-Type: application/json"   -d '{"id":"bad-1","algorithm":"BAD"}' "$BASE/devices"

# 10) Duplicate ID → 409
curl -sS -o /dev/null -w "%{http_code}
"   -H "Content-Type: application/json"   -d '{"id":"dev-1","algorithm":"RSA"}' "$BASE/devices"

# 11) Missing device on sign → 404
curl -sS -o /dev/null -w "%{http_code}
"   -H "Content-Type: application/json"   -d '{"data":"x"}' "$BASE/devices/nope/sign"

# 12) Empty data on sign → 400
curl -sS -o /dev/null -w "%{http_code}
"   -H "Content-Type: application/json"   -d '{"data":""}' "$BASE/devices/dev-1/sign"
```

---

## Cryptographic Verification (optional)

Verify `SIG1` against `SIGNED1` with the device’s public key.

```bash
# Save device public key and the first signature/message you captured earlier
curl -sS "$BASE/devices/dev-1" > /tmp/dev1.json
jq -r '.public_key_pem' /tmp/dev1.json > /tmp/dev1_pub.pem

printf "%s" "$SIG1"   | base64 -d > /tmp/sig1.bin
printf "%s" "$SIGNED1"            > /tmp/msg1.txt

# If PEM is "RSA PUBLIC KEY", convert to SPKI:
if head -1 /tmp/dev1_pub.pem | grep -q "RSA PUBLIC KEY"; then
  openssl rsa -RSAPublicKey_in -in /tmp/dev1_pub.pem -pubin -out /tmp/dev1_pub_spki.pem
  PUB=/tmp/dev1_pub_spki.pem
else
  PUB=/tmp/dev1_pub.pem
fi

# Verify (RSA PKCS#1 v1.5 SHA-256, or ECDSA ASN.1 SHA-256)
openssl dgst -sha256 -verify "$PUB" -signature /tmp/sig1.bin /tmp/msg1.txt
```

> If you want to verify `SIG2`/`SIGNED2`, repeat with those variables instead.  
> Ensure you always verify the **exact pair**.

---

## Concurrency & Correctness

- **Atomic Sign + Increment:** repository exposes `Update(id, fn)` which:
  1. Locks the device,
  2. Runs the provided closure that signs data, sets `last_signature_base64`, and bumps `signature_counter`,
  3. Stores the updated device.
- Because all of that happens under the same lock, two concurrent sign calls on the same device cannot interleave and cannot skip counter values.

- **Monotonic & Gap-free:** the counter is incremented exactly once per successful sign, inside that same atomic update.

- **Read vs Write isolation:** `Get`/`List` use read access; `Create`/`Update` use writes + locking. The storage interface is ready to be swapped with a SQL-backed repo that uses `SELECT ... FOR UPDATE`.

---

## Extensibility

- **New algorithms:**  
  Add a new struct that implements `domain.Signer` (`Sign([]byte)`, `Verify`, `PublicPEM`, `AlgorithmName`).  
  Add a constructor in the signer factory.  
  No changes needed in the core service or HTTP layer.

- **Persistence:**  
  Swap `storage.Memory` with a DB-backed repo that still obeys `Update(id, fn)` atomic semantics.

- **Infra:**  
  Current stack is stdlib `net/http`. You can plug chi / gin / echo without touching domain/service.

---

## Configuration

- `cmd/signature-service/main.go` takes:
  - `-mode=http` (current supported mode)
  - `-addr=:8080` (listen address)
  - `-t` (test/dry-run: build server but don’t actually listen)

Main wires:
- `storage.NewMemory()`
- `service.New(repo, factory{}, id.UUIDv4{})`
- `http.Start(ctx, addr, svc, test)`

---

## AI Tools Disclosure

- **ChatGPT (GPT-5 Thinking)** was used to:
  - discuss the draft handlers, service logic, and repo interface patterns,
  - generate tests for 100% coverage (including concurrency-safe Update, panic recovery middleware, and main.go exit paths),
  - collaborate with this README and the cURL cookbook.

- All code paths and concurrency guarantees were reasoned about and validated manually (especially monotonic counter, signature chaining, and RSA/ECDSA verification).

---

## Future Work

- Replace in-memory repo with Postgres using row-level locks to keep the same atomic `Update` semantics.
- Add idempotency keys for `Sign` to make retry-safe.
- Add auth / multi-tenant isolation.
- Hook metrics + structured logging.
- Support HSM/KMS-backed private keys / key rotation policy.
