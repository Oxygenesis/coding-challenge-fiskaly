package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"

	"example.com/fiskaly/signature/internal/domain"
)

var rsaGenerateKey = rsa.GenerateKey

type RSASigner struct {
	priv   *rsa.PrivateKey
	pubPEM string
}

func NewRSASigner(bits int) (*RSASigner, error) {
	k, err := rsaGenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	pubDER := x509.MarshalPKCS1PublicKey(&k.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubDER})
	return &RSASigner{priv: k, pubPEM: string(pemBytes)}, nil
}

func (s *RSASigner) Sign(payload []byte) ([]byte, error) {
	h := sha256.Sum256(payload)
	return rsa.SignPKCS1v15(rand.Reader, s.priv, crypto.SHA256, h[:])
}
func (s *RSASigner) Verify(payload, signature []byte) bool {
	h := sha256.Sum256(payload)
	return rsa.VerifyPKCS1v15(&s.priv.PublicKey, crypto.SHA256, h[:], signature) == nil
}
func (s *RSASigner) PublicPEM() string     { return s.pubPEM }
func (s *RSASigner) AlgorithmName() string { return "RSA" }

var _ domain.Signer = (*RSASigner)(nil)
