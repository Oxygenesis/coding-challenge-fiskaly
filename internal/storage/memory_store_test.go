package storage

import (
	"errors"
	"testing"

	"github.com/oxygenesis/signature/internal/domain"
)

type fakeSigner struct{}

func (fakeSigner) Sign(p []byte) ([]byte, error) { return []byte("sig"), nil }
func (fakeSigner) Verify(p, s []byte) bool       { return true }
func (fakeSigner) PublicPEM() string             { return "PEM" }
func (fakeSigner) AlgorithmName() string         { return "RSA" }

func TestMemoryCRUD(t *testing.T) {
	m := NewMemory()
	d := &domain.SignatureDevice{ID: "x", Algorithm: domain.AlgRSA}
	if err := m.Create(d, fakeSigner{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(d, fakeSigner{}); err == nil {
		t.Fatal("expected conflict")
	}
	got, s, err := m.Get("x")
	if err != nil || got.ID != "x" || s == nil {
		t.Fatal("get failed")
	}
	list, _ := m.List()
	if len(list) != 1 {
		t.Fatal("list failed")
	}
	if err := m.Update("x", func(dev *domain.SignatureDevice, signer domain.Signer) error {
		dev.Label = "L"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, _, _ = m.Get("x")
	if got.Label != "L" {
		t.Fatal("update didn't persist")
	}
	if _, _, err := m.Get("missing"); err == nil {
		t.Fatal("expected not found")
	}
	if err := m.Update("missing", func(*domain.SignatureDevice, domain.Signer) error { return nil }); err == nil {
		t.Fatal("expected not found on update")
	}
}

type fakeSigner2 struct{}

func (fakeSigner2) Sign(p []byte) ([]byte, error) { return []byte("sig"), nil }
func (fakeSigner2) Verify(p, s []byte) bool       { return true }
func (fakeSigner2) PublicPEM() string             { return "PEM" }
func (fakeSigner2) AlgorithmName() string         { return "RSA" }

func TestUpdate_FnError(t *testing.T) {
	m := NewMemory()
	d := &domain.SignatureDevice{ID: "x", Algorithm: domain.AlgRSA}
	if err := m.Create(d, fakeSigner2{}); err != nil {
		t.Fatal(err)
	}
	want := errors.New("fn error")
	if err := m.Update("x", func(*domain.SignatureDevice, domain.Signer) error { return want }); !errors.Is(err, want) {
		t.Fatalf("got %v want %v", err, want)
	}
}
