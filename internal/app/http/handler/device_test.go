package handler_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"example.com/fiskaly/signature/internal/app/http/handler"
	"example.com/fiskaly/signature/internal/domain"
	"example.com/fiskaly/signature/internal/service"
	"example.com/fiskaly/signature/internal/storage"
)

// fakes
type fakeSigner struct{}

func (fakeSigner) Sign(p []byte) ([]byte, error) { return []byte("sig"), nil }
func (fakeSigner) Verify(p, s []byte) bool       { return true }
func (fakeSigner) PublicPEM() string             { return "PEM" }
func (fakeSigner) AlgorithmName() string         { return "RSA" }

type fakeFactory struct{}

func (fakeFactory) NewRSA(int) (domain.Signer, error) { return fakeSigner{}, nil }
func (fakeFactory) NewECDSA() (domain.Signer, error)  { return fakeSigner{}, nil }

type errCreateRepo struct{ storage.Memory }

func (errCreateRepo) Create(*domain.SignatureDevice, domain.Signer) error {
	return errors.New("db down")
}

type errListRepo struct{ storage.Memory }

func (errListRepo) List() ([]*domain.SignatureDevice, error) { return nil, errors.New("boom") }

type errUpdateRepo struct{ storage.Memory }

func (errUpdateRepo) Update(string, func(*domain.SignatureDevice, domain.Signer) error) error {
	return errors.New("update fail")
}

func rrDo(h http.HandlerFunc, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func Test_Health_Dispatch(t *testing.T) {
	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	hd := handler.NewDevice(svc)

	if rr := rrDo(hd.Health, http.MethodGet, "/v1/health", nil); rr.Code != http.StatusOK {
		t.Fatalf("GET health=%d", rr.Code)
	}
	if rr := rrDo(hd.Health, http.MethodPost, "/v1/health", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("POST health=%d", rr.Code)
	}
}

func Test_Devices_Create_List_And_Methods(t *testing.T) {
	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	hd := handler.NewDevice(svc)

	// create: missing id -> 400
	if rr := rrDo(hd.Devices, http.MethodPost, "/v1/devices", bytes.NewReader([]byte(`{"algorithm":"RSA"}`))); rr.Code != http.StatusBadRequest {
		t.Fatalf("create missing id=%d", rr.Code)
	}
	// list: ok
	if rr := rrDo(hd.Devices, http.MethodGet, "/v1/devices", nil); rr.Code != http.StatusOK {
		t.Fatalf("list=%d", rr.Code)
	}
	// unknown method -> 404
	if rr := rrDo(hd.Devices, http.MethodDelete, "/v1/devices", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("delete devices=%d", rr.Code)
	}
}

func Test_Create_Variants(t *testing.T) {
	// invalid JSON
	svc := service.New(storage.NewMemory(), fakeFactory{}, nil)
	hd := handler.NewDevice(svc)
	if rr := rrDo(hd.Create, http.MethodPost, "/v1/devices", bytes.NewReader([]byte("{"))); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON=%d", rr.Code)
	}
	// invalid algorithm -> 400 (service validates)
	if rr := rrDo(hd.Create, http.MethodPost, "/v1/devices", bytes.NewReader([]byte(`{"id":"x","algorithm":"BAD"}`))); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid algo=%d", rr.Code)
	}
	// repo error -> 500
	svc2 := service.New(&errCreateRepo{}, fakeFactory{}, nil)
	hd2 := handler.NewDevice(svc2)
	if rr := rrDo(hd2.Create, http.MethodPost, "/v1/devices", bytes.NewReader([]byte(`{"id":"x","algorithm":"RSA"}`))); rr.Code != http.StatusInternalServerError {
		t.Fatalf("repo err=%d", rr.Code)
	}
	// happy path -> 201
	svc3 := service.New(storage.NewMemory(), fakeFactory{}, nil)
	hd3 := handler.NewDevice(svc3)
	if rr := rrDo(hd3.Create, http.MethodPost, "/v1/devices", bytes.NewReader([]byte(`{"id":"dev-1","algorithm":"RSA","label":"L"}`))); rr.Code != http.StatusCreated {
		t.Fatalf("create ok=%d", rr.Code)
	}
}

func Test_List_RepoError_500(t *testing.T) {
	svc := service.New(&errListRepo{}, fakeFactory{}, nil)
	hd := handler.NewDevice(svc)
	if rr := rrDo(hd.List, http.MethodGet, "/v1/devices", nil); rr.Code != http.StatusInternalServerError {
		t.Fatalf("list repo err=%d", rr.Code)
	}
}

func Test_Get_NotFound_Then_OK(t *testing.T) {
	mem := storage.NewMemory()
	svc := service.New(mem, fakeFactory{}, nil)
	hd := handler.NewDevice(svc)

	if rr := rrDo(func(w http.ResponseWriter, r *http.Request) { hd.Get(w, r, "missing") }, http.MethodGet, "/v1/devices/missing", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("get missing=%d", rr.Code)
	}
	_, _ = svc.CreateDevice("dev-1", domain.AlgRSA, "")
	if rr := rrDo(func(w http.ResponseWriter, r *http.Request) { hd.Get(w, r, "dev-1") }, http.MethodGet, "/v1/devices/dev-1", nil); rr.Code != http.StatusOK {
		t.Fatalf("get ok=%d", rr.Code)
	}
}

func Test_Sign_Flows(t *testing.T) {
	mem := storage.NewMemory()
	svc := service.New(mem, fakeFactory{}, nil)
	hd := handler.NewDevice(svc)

	// invalid JSON
	if rr := rrDo(func(w http.ResponseWriter, r *http.Request) { hd.Sign(w, r, "dev-1") }, http.MethodPost, "/v1/devices/dev-1/sign", bytes.NewReader([]byte("{"))); rr.Code != http.StatusBadRequest {
		t.Fatalf("sign invalid json=%d", rr.Code)
	}
	// create device
	_, _ = svc.CreateDevice("dev-1", domain.AlgRSA, "")
	// empty data -> 400 (ErrInvalidInput)
	empty, _ := json.Marshal(map[string]any{"data": ""})
	if rr := rrDo(func(w http.ResponseWriter, r *http.Request) { hd.Sign(w, r, "dev-1") }, http.MethodPost, "/v1/devices/dev-1/sign", bytes.NewReader(empty)); rr.Code != http.StatusBadRequest {
		t.Fatalf("sign empty=%d", rr.Code)
	}
	// ok
	ok, _ := json.Marshal(map[string]any{"data": "hello"})
	if rr := rrDo(func(w http.ResponseWriter, r *http.Request) { hd.Sign(w, r, "dev-1") }, http.MethodPost, "/v1/devices/dev-1/sign", bytes.NewReader(ok)); rr.Code != http.StatusOK {
		t.Fatalf("sign ok=%d", rr.Code)
	}
}

func Test_DeviceOps_Fallthroughs_And_WrongMethods(t *testing.T) {
	mem := storage.NewMemory()
	s := service.New(mem, fakeFactory{}, nil)
	hd := handler.NewDevice(s)

	// rest == ""  -> 404
	req := httptest.NewRequest(http.MethodGet, "/v1/devices/", nil)
	rr := httptest.NewRecorder()
	hd.DeviceOps(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("empty rest status=%d", rr.Code)
	}

	// "/sign" but empty id -> 404
	req = httptest.NewRequest(http.MethodPost, "/v1/devices//sign", bytes.NewReader([]byte(`{"data":"hi"}`)))
	req.Header.Set("content-type", "application/json")
	rr = httptest.NewRecorder()
	hd.DeviceOps(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("empty id before /sign status=%d", rr.Code)
	}

	// "/sign" with GET (wrong method) -> final 404
	req = httptest.NewRequest(http.MethodGet, "/v1/devices/dev-1/sign", nil)
	rr = httptest.NewRecorder()
	hd.DeviceOps(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("wrong method on sign status=%d", rr.Code)
	}

	// GET /v1/devices/dev-1/extra -> final 404 (contains slash)
	req = httptest.NewRequest(http.MethodGet, "/v1/devices/dev-1/extra", nil)
	rr = httptest.NewRecorder()
	hd.DeviceOps(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get extra path status=%d", rr.Code)
	}
}

func Test_Sign_NotFound_404(t *testing.T) {
	mem := storage.NewMemory()
	s := service.New(mem, fakeFactory{}, nil)
	hd := handler.NewDevice(s)

	body, _ := json.Marshal(map[string]any{"data": "hello"})
	rr := rrDo(func(w http.ResponseWriter, r *http.Request) { hd.Sign(w, r, "missing") },
		http.MethodPost, "/v1/devices/missing/sign", bytes.NewReader(body))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("sign not found status=%d", rr.Code)
	}
}

func Test_Create_AlreadyExists_409(t *testing.T) {
	mem := storage.NewMemory()
	s := service.New(mem, fakeFactory{}, nil)
	hd := handler.NewDevice(s)

	// first create OK
	if rr := rrDo(hd.Create, http.MethodPost, "/v1/devices",
		bytes.NewReader([]byte(`{"id":"dup","algorithm":"RSA"}`))); rr.Code != http.StatusCreated {
		t.Fatalf("first create status=%d", rr.Code)
	}
	// duplicate -> 409
	if rr := rrDo(hd.Create, http.MethodPost, "/v1/devices",
		bytes.NewReader([]byte(`{"id":"dup","algorithm":"RSA"}`))); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate create status=%d", rr.Code)
	}
}

type errGetRepo struct{ storage.Memory }

func (errGetRepo) Get(string) (*domain.SignatureDevice, domain.Signer, error) {
	return nil, nil, errors.New("db oops")
}

func Test_Get_InternalError_500(t *testing.T) {
	s := service.New(&errGetRepo{}, fakeFactory{}, nil)
	hd := handler.NewDevice(s)
	rr := rrDo(func(w http.ResponseWriter, r *http.Request) { hd.Get(w, r, "any") },
		http.MethodGet, "/v1/devices/any", nil)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("get 500 status=%d", rr.Code)
	}
}

// helper
func rr(method, path string, body []byte, h http.HandlerFunc) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

// --- 1) SIGN default branch (500) ---
func Test_Sign_Default_InternalError_500(t *testing.T) {
	mem := storage.NewMemory()
	svc := service.New(&errUpdateRepo{*mem}, fakeFactory{}, nil)
	// device must exist so Sign tries Update and gets our error
	if _, err := svc.CreateDevice("dev-x", domain.AlgRSA, ""); err != nil {
		t.Fatal(err)
	}
	hd := handler.NewDevice(svc)

	b, _ := json.Marshal(map[string]any{"data": "hello"})
	rr := rr("POST", "/v1/devices/dev-x/sign", b, func(w http.ResponseWriter, r *http.Request) {
		hd.Sign(w, r, "dev-x")
	})
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", rr.Code)
	}
}

// --- 2) DEVICEOPS: cover the `h.Sign(...); return` branch ---
func Test_DeviceOps_SignBranch_ReturnCovered(t *testing.T) {
	mem := storage.NewMemory()
	svc := service.New(mem, fakeFactory{}, nil)
	_, _ = svc.CreateDevice("dev-ok", domain.AlgRSA, "")
	hd := handler.NewDevice(svc)

	b, _ := json.Marshal(map[string]any{"data": "hello"})
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/dev-ok/sign", bytes.NewReader(b))
	req.Header.Set("content-type", "application/json")
	rr := httptest.NewRecorder()
	hd.DeviceOps(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	// executing through this path covers the `h.Sign(...); return` line
}

// --- 3) DEVICEOPS: cover the `h.Get(...); return` branch ---
func Test_DeviceOps_GetBranch_ReturnCovered(t *testing.T) {
	mem := storage.NewMemory()
	svc := service.New(mem, fakeFactory{}, nil)
	_, _ = svc.CreateDevice("dev-get", domain.AlgRSA, "")
	hd := handler.NewDevice(svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/devices/dev-get", nil)
	rr := httptest.NewRecorder()
	hd.DeviceOps(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	// executing through this path covers the `h.Get(...); return` line
}
