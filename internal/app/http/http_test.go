package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oxygenesis/signature/internal/app/http/handler"
	"github.com/oxygenesis/signature/internal/domain"
	"github.com/oxygenesis/signature/internal/service"
	"github.com/oxygenesis/signature/internal/storage"
)

// --- fakes/stubs used here ---

type fakeSigner struct{}

func (fakeSigner) Sign(p []byte) ([]byte, error) { return []byte("sig"), nil }
func (fakeSigner) Verify(p, s []byte) bool       { return true }
func (fakeSigner) PublicPEM() string             { return "PEM" }
func (fakeSigner) AlgorithmName() string         { return "RSA" }

type fakeFactory struct{}

func (fakeFactory) NewRSA(int) (domain.Signer, error) { return fakeSigner{}, nil }
func (fakeFactory) NewECDSA() (domain.Signer, error)  { return fakeSigner{}, nil }

// repo that fails at Create
type errCreateRepo struct{ storage.Memory }

func (errCreateRepo) Create(*domain.SignatureDevice, domain.Signer) error {
	return errors.New("db down")
}

// repo that fails at List
type errListRepo struct{ storage.Memory }

func (errListRepo) List() ([]*domain.SignatureDevice, error) { return nil, errors.New("boom") }

// repo that returns device but Update fails (to hit POST /sign 500)
type errUpdateRepo struct {
	storage.Memory
}

func (r *errUpdateRepo) Update(id string, fn func(*domain.SignatureDevice, domain.Signer) error) error {
	return errors.New("update fail")
}

func Test_Start_TestMode(t *testing.T) {
	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	if err := Start(nil, ":0", svc, true); err != nil {
		t.Fatalf("start test mode: %v", err)
	}
}

func Test_Routes_HappyFlow(t *testing.T) {
	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	srv := buildServer(":0", svc)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	// health
	res, _ := http.Get(ts.URL + "/v1/health")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health %d", res.StatusCode)
	}

	// create
	b, _ := json.Marshal(map[string]any{"id": "dev-1", "algorithm": "RSA", "label": "L"})
	res, _ = http.Post(ts.URL+"/v1/devices", "application/json", bytes.NewReader(b))
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create %d", res.StatusCode)
	}

	// sign
	b, _ = json.Marshal(map[string]any{"data": "hello"})
	res, _ = http.Post(ts.URL+"/v1/devices/dev-1/sign", "application/json", bytes.NewReader(b))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign %d", res.StatusCode)
	}

	// get
	res, _ = http.Get(ts.URL + "/v1/devices/dev-1")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get %d", res.StatusCode)
	}

	// list
	res, _ = http.Get(ts.URL + "/v1/devices")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list %d", res.StatusCode)
	}
}

func Test_Create_InvalidAlgorithm_Maps400(t *testing.T) {
	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	srv := buildServer(":0", svc)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	b, _ := json.Marshal(map[string]any{"id": "x", "algorithm": "BAD"})
	res, _ := http.Post(ts.URL+"/v1/devices", "application/json", bytes.NewReader(b))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", res.StatusCode)
	}
}

func Test_Create_RepoError_500(t *testing.T) {
	svc := service.New(&errCreateRepo{}, fakeFactory{}, nil)
	srv := buildServer(":0", svc)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	b, _ := json.Marshal(map[string]any{"id": "x", "algorithm": "RSA"})
	res, _ := http.Post(ts.URL+"/v1/devices", "application/json", bytes.NewReader(b))
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", res.StatusCode)
	}
}

func Test_List_RepoError_500(t *testing.T) {
	svc := service.New(&errListRepo{}, fakeFactory{}, nil)
	srv := buildServer(":0", svc)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	res, _ := http.Get(ts.URL + "/v1/devices")
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", res.StatusCode)
	}
}

func Test_Get_NotFound_404(t *testing.T) {
	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	srv := buildServer(":0", svc)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	res, _ := http.Get(ts.URL + "/v1/devices/missing")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d", res.StatusCode)
	}
}

func Test_Sign_InvalidJSON_400(t *testing.T) {
	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	srv := buildServer(":0", svc)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	res, _ := http.Post(ts.URL+"/v1/devices/dev-1/sign", "application/json", bytes.NewReader([]byte("{")))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", res.StatusCode)
	}
}

func Test_Sign_ErrInvalidInput_400(t *testing.T) {
	// create device first
	mem := storage.NewMemory()
	svc := service.New(mem, fakeFactory{}, nil)
	_, _ = svc.CreateDevice("dev-1", domain.AlgRSA, "")
	srv := buildServer(":0", svc)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	// empty data => service returns ErrInvalidInput -> 400
	b, _ := json.Marshal(map[string]any{"data": ""})
	res, _ := http.Post(ts.URL+"/v1/devices/dev-1/sign", "application/json", bytes.NewReader(b))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", res.StatusCode)
	}
}

func Test_Sign_InternalError_500(t *testing.T) {
	// prepare repo that will fail Update
	mem := storage.NewMemory()
	svc := service.New(&errUpdateRepo{*mem}, fakeFactory{}, nil)
	_, _ = svc.CreateDevice("dev-1", domain.AlgRSA, "")

	srv := buildServer(":0", svc)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	b, _ := json.Marshal(map[string]any{"data": "hello"})
	res, _ := http.Post(ts.URL+"/v1/devices/dev-1/sign", "application/json", bytes.NewReader(b))
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", res.StatusCode)
	}
}

// sanity: helpers visible to tests because we’re in same package.
var _ = handler.NewDevice

func TestStart_TestMode(t *testing.T) {
	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	if err := Start(context.Background(), ":0", svc, true); err != nil {
		t.Fatalf("start test mode: %v", err)
	}
}

func TestStart_ServeBranch_WithStub(t *testing.T) {
	orig := listenAndServe
	defer func() { listenAndServe = orig }()

	called := false
	listenAndServe = func(srv *http.Server) error {
		if srv == nil || srv.Handler == nil {
			t.Fatal("nil server/handler")
		}
		called = true
		return nil
	}

	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	if err := Start(context.Background(), ":0", svc, false); err != nil {
		t.Fatalf("start serve stub err: %v", err)
	}
	if !called {
		t.Fatal("listenAndServe not called")
	}
}

func TestBuildServer_Routes(t *testing.T) {
	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	srv := buildServer(":0", svc)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	// create device
	b, _ := json.Marshal(map[string]any{"id": "dev-1", "algorithm": "RSA"})
	res, _ := http.Post(ts.URL+"/v1/devices", "application/json", bytes.NewReader(b))
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d", res.StatusCode)
	}
	// sign
	b, _ = json.Marshal(map[string]any{"data": "hello"})
	res, _ = http.Post(ts.URL+"/v1/devices/dev-1/sign", "application/json", bytes.NewReader(b))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign status=%d", res.StatusCode)
	}
}

func TestDefaultListenAndServe_ReturnsError(t *testing.T) {
	// invalid port forces immediate error without binding
	srv := &http.Server{Addr: "127.0.0.1:-1", Handler: http.NewServeMux()}
	if err := defaultListenAndServe(srv); err == nil {
		t.Fatal("expected error from defaultListenAndServe on invalid addr")
	}
}
