package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"io"
	"testing"
)

func TestRSAAndECDSA(t *testing.T) {
	// RSA
	rs, err := NewRSASigner(1024)
	if err != nil {
		t.Fatal(err)
	}
	p := []byte("payload")
	sig, err := rs.Sign(p)
	if err != nil {
		t.Fatal(err)
	}
	if !rs.Verify(p, sig) {
		t.Fatal("rsa verify failed")
	}
	if rs.PublicPEM() == "" || rs.AlgorithmName() != "RSA" {
		t.Fatal("rsa meta failed")
	}

	// ECDSA
	es, err := NewECDSASigner()
	if err != nil {
		t.Fatal(err)
	}
	sig, err = es.Sign(p)
	if err != nil {
		t.Fatal(err)
	}
	if !es.Verify(p, sig) {
		t.Fatal("ecdsa verify failed")
	}
	if es.PublicPEM() == "" || es.AlgorithmName() != "ECC" {
		t.Fatal("ecdsa meta failed")
	}
}

func TestRSASigner_New_Error(t *testing.T) {
	old := rsaGenerateKey
	rsaGenerateKey = func(io.Reader, int) (*rsa.PrivateKey, error) { return nil, errors.New("boom") }
	defer func() { rsaGenerateKey = old }()
	if _, err := NewRSASigner(1024); err == nil {
		t.Fatal("want error")
	}
}

func TestECDSASigner_New_Errors(t *testing.T) {
	// ecdsa.GenerateKey error
	oldGen := ecdsaGenerateKey
	ecdsaGenerateKey = func(curve elliptic.Curve, r io.Reader) (*ecdsa.PrivateKey, error) { return nil, errors.New("gen err") }
	if _, err := NewECDSASigner(); err == nil {
		t.Fatal("want gen err")
	}
	ecdsaGenerateKey = oldGen

	// marshal error
	oldMarshal := marshalPKIXPublicKey
	marshalPKIXPublicKey = func(any) ([]byte, error) { return nil, errors.New("marshal err") }
	defer func() { marshalPKIXPublicKey = oldMarshal }()
	if _, err := NewECDSASigner(); err == nil {
		t.Fatal("want marshal err")
	}
}
