//go:build smokebin

package main

import (
	"bytes"
	goCrypto "crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/oxygenesis/signature/internal/app/http/handler"
	"github.com/oxygenesis/signature/internal/app/http/middleware"
	"github.com/oxygenesis/signature/internal/crypto"
	"github.com/oxygenesis/signature/internal/domain"
	"github.com/oxygenesis/signature/internal/service"
	"github.com/oxygenesis/signature/internal/storage"
	"github.com/oxygenesis/signature/pkg/id"
)

const apiPrefix = "/v1" // adjust to "" if your routes don’t use /v1

type factory struct{}

func (factory) NewRSA(bits int) (domain.Signer, error) { return crypto.NewRSASigner(bits) }
func (factory) NewECDSA() (domain.Signer, error)       { return crypto.NewECDSASigner() }

// must fails the smoke test immediately with a helpful message.
func must(ok bool, msg string, args ...any) {
	if !ok {
		log.Fatalf("SMOKE FAIL: "+msg, args...)
	}
}

func main() {
	// Wire the app with an in-process server (no real port binding).
	repo := storage.NewMemory()
	svc := service.New(repo, factory{}, id.UUIDv4{})

	dev := handler.NewDevice(svc)
	mux := http.NewServeMux()
	mux.HandleFunc(apiPrefix+"/health", dev.Health)
	mux.HandleFunc(apiPrefix+"/devices", dev.Devices)
	mux.HandleFunc(apiPrefix+"/devices/", dev.DeviceOps)

	ts := httptest.NewServer(middleware.Recovery(mux))
	defer ts.Close()

	do := func(method, path string, body any) (int, []byte) {
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		req.Header.Set("content-type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		fmt.Printf("%d %s\n\n", resp.StatusCode, string(b))
		return resp.StatusCode, b
	}

	// 1) Health
	code, body := do("GET", apiPrefix+"/health", nil)
	must(code == 200, "health status=%d", code)
	var health struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(body, &health)
	must(health.Status == "ok", "health body=%s", string(body))

	// 2) Create device (RSA)
	deviceID := "dev-1"
	code, body = do("POST", apiPrefix+"/devices", map[string]any{
		"id":        deviceID,
		"algorithm": "RSA",
		"label":     "L",
	})
	must(code == 201, "create status=%d body=%s", code, string(body))

	type deviceResp struct {
		ID               string `json:"id"`
		Algorithm        string `json:"algorithm"`
		Label            string `json:"label"`
		SignatureCounter uint64 `json:"signature_counter"`
		LastSignatureB64 string `json:"last_signature_base64"`
		PublicKeyPEM     string `json:"public_key_pem"`
	}
	var devOut deviceResp
	if err := json.Unmarshal(body, &devOut); err != nil {
		log.Fatalf("SMOKE FAIL: create unmarshal: %v", err)
	}
	must(devOut.ID == deviceID, "unexpected id: %q", devOut.ID)
	must(devOut.Algorithm == "RSA", "unexpected algorithm: %q", devOut.Algorithm)
	must(devOut.SignatureCounter == 0, "counter=%d", devOut.SignatureCounter)
	must(devOut.LastSignatureB64 == "", "last_signature_base64 should be empty on create")
	must(strings.HasPrefix(devOut.PublicKeyPEM, "-----BEGIN"), "missing public key PEM")

	// 3) Sign "hello" and check invariants
	code, body = do("POST", apiPrefix+"/devices/"+deviceID+"/sign", map[string]any{"data": "hello"})
	must(code == 200, "sign status=%d body=%s", code, string(body))

	type signResp struct {
		Signature  string `json:"signature"`
		SignedData string `json:"signed_data"`
	}
	var sr signResp
	if err := json.Unmarshal(body, &sr); err != nil {
		log.Fatalf("SMOKE FAIL: sign unmarshal: %v", err)
	}
	must(sr.Signature != "", "signature empty")
	must(strings.HasPrefix(sr.SignedData, "0_hello_"), "signed_data=%q", sr.SignedData)
	parts := strings.Split(sr.SignedData, "_")
	must(len(parts) == 3, "signed_data parts=%d (%q)", len(parts), sr.SignedData)
	must(parts[2] == base64.StdEncoding.EncodeToString([]byte(deviceID)),
		"base case last should be base64(id): got %q", parts[2])

	// Verify signature with returned public key (works for RSA/PKIX or RSA/PKCS#1)
	verify(sr.Signature, sr.SignedData, devOut.PublicKeyPEM)

	// 4) Get device; counter advanced and last_signature matches
	code, body = do("GET", apiPrefix+"/devices/"+deviceID, nil)
	must(code == 200, "get status=%d body=%s", code, string(body))

	var dev2 deviceResp
	if err := json.Unmarshal(body, &dev2); err != nil {
		log.Fatalf("SMOKE FAIL: get unmarshal: %v", err)
	}
	must(dev2.SignatureCounter == 1, "counter=%d", dev2.SignatureCounter)
	must(dev2.LastSignatureB64 == sr.Signature, "last_signature mismatch")
}

// verify checks the signature against signedData using the PEM public key.
// Supports RSA (PKCS#1 "RSA PUBLIC KEY" or PKIX "PUBLIC KEY") and ECDSA (PKIX).
func verify(sigB64, signedData, pubPEM string) {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	must(err == nil, "decode signature: %v", err)

	block, _ := pem.Decode([]byte(pubPEM))
	must(block != nil, "pem decode failed")

	var pub any
	switch block.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		must(err == nil, "parse PKIX public key: %v", err)
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		must(err == nil, "parse PKCS#1 public key: %v", err)
	default:
		must(false, "unknown PEM type %q", block.Type)
	}

	digest := sha256.Sum256([]byte(signedData))

	switch k := pub.(type) {
	case *rsa.PublicKey:
		// IMPORTANT: pass crypto.SHA256 (constant), not bytes.
		err = rsa.VerifyPKCS1v15(k, goCrypto.SHA256, digest[:], sig)
		must(err == nil, "rsa verify failed: %v", err)
	case *ecdsa.PublicKey:
		ok := ecdsa.VerifyASN1(k, digest[:], sig)
		must(ok, "ecdsa verify failed")
	default:
		must(false, "unexpected public key type %T", pub)
	}
}
