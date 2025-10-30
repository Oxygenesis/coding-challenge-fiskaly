package service

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"example.com/fiskaly/signature/internal/domain"
	"example.com/fiskaly/signature/internal/storage"
)

type fakeFactory struct{}

func (fakeFactory) NewRSA(bits int) (domain.Signer, error) { return fakeSigner{}, nil }
func (fakeFactory) NewECDSA() (domain.Signer, error)       { return fakeSigner{}, nil }

type fakeSigner struct{}

func (fakeSigner) Sign(p []byte) ([]byte, error) { return []byte("sig"), nil }
func (fakeSigner) Verify(p, s []byte) bool       { return true }
func (fakeSigner) PublicPEM() string             { return "PEM" }
func (fakeSigner) AlgorithmName() string         { return "RSA" }

type fakeIDs struct{}

func (fakeIDs) New() string { return "id" }

func TestCreateGetListSign(t *testing.T) {
	svc := New(storage.NewMemory(), fakeFactory{}, fakeIDs{})
	// invalid
	if _, err := svc.CreateDevice("", domain.AlgRSA, ""); err == nil {
		t.Fatal("want invalid input")
	}
	// invalid algorithm
	if _, err := svc.CreateDevice("x", "BAD", ""); err == nil {
		t.Fatal("want invalid algo")
	}
	// create OK
	if _, err := svc.CreateDevice("x", domain.AlgRSA, "L"); err != nil {
		t.Fatal(err)
	}
	// duplicate
	if _, err := svc.CreateDevice("x", domain.AlgRSA, "L"); err == nil {
		t.Fatal("want conflict")
	}
	// get
	if _, err := svc.GetDevice("x"); err != nil {
		t.Fatal(err)
	}
	// list
	if list, err := svc.ListDevices(); err != nil || len(list) != 1 {
		t.Fatal("list failed")
	}
	// sign
	res, err := svc.Sign("x", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if res.SignatureB64 == "" || !strings.Contains(res.SignedData, "_hello_") {
		t.Fatalf("bad sign result: %+v", res)
	}
	// sign invalid data
	if _, err := svc.Sign("x", ""); err == nil {
		t.Fatal("want invalid input")
	}
	// sign missing id
	if _, err := svc.Sign("missing", "hi"); err == nil {
		t.Fatal("want not found")
	}
}

func TestConcurrentSign_NoGaps(t *testing.T) {
	svc := New(storage.NewMemory(), fakeFactory{}, fakeIDs{})
	_, _ = svc.CreateDevice("dev", domain.AlgRSA, "")
	const N = 60
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			if _, err := svc.Sign("dev", "x"); err != nil {
				t.Errorf("sign err: %v", err)
			}
		}()
	}
	wg.Wait()
	d, _ := svc.GetDevice("dev")
	if d.SignatureCounter != N {
		t.Fatalf("counter=%d want=%d", d.SignatureCounter, N)
	}
}

// --- error branches ---

type errFactory struct{}

func (errFactory) NewRSA(int) (domain.Signer, error) { return nil, errors.New("factory") }
func (errFactory) NewECDSA() (domain.Signer, error)  { return nil, errors.New("factory") }

func TestCreateDevice_FactoryError(t *testing.T) {
	svc := New(storage.NewMemory(), errFactory{}, fakeIDs{})
	if _, err := svc.CreateDevice("x", domain.AlgRSA, ""); err == nil {
		t.Fatal("want factory error")
	}
}

type errSigner struct{}

func (errSigner) Sign([]byte) ([]byte, error) { return nil, errors.New("sign fail") }
func (errSigner) Verify([]byte, []byte) bool  { return true }
func (errSigner) PublicPEM() string           { return "PEM" }
func (errSigner) AlgorithmName() string       { return "RSA" }

// repo that swaps in a bad signer so Update sees it
type repoWithBadSigner struct{ *storage.Memory }

func (r *repoWithBadSigner) Create(d *domain.SignatureDevice, _ domain.Signer) error {
	return r.Memory.Create(d, errSigner{})
}

func TestSign_SignerError(t *testing.T) {
	repo := &repoWithBadSigner{storage.NewMemory()}
	svc := New(repo, fakeFactory{}, fakeIDs{})
	if _, err := svc.CreateDevice("x", domain.AlgRSA, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Sign("x", "hi"); err == nil {
		t.Fatal("want signer error")
	}
}

func TestCreateDevice_ECCPath(t *testing.T) {
	svc := New(storage.NewMemory(), fakeFactory{}, fakeIDs{})
	dev, err := svc.CreateDevice("ecc-1", domain.AlgECC, "L")
	if err != nil {
		t.Fatalf("CreateDevice ECC err: %v", err)
	}
	if dev == nil || dev.Algorithm != domain.AlgECC {
		t.Fatalf("unexpected device: %+v", dev)
	}
}
