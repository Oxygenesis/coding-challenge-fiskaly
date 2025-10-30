package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"

	"example.com/fiskaly/signature/internal/domain"
)

var ecdsaGenerateKey = ecdsa.GenerateKey
var marshalPKIXPublicKey = x509.MarshalPKIXPublicKey

type ECDSASigner struct {
	priv   *ecdsa.PrivateKey
	pubPEM string
}

func NewECDSASigner() (*ECDSASigner, error) {
	k, err := ecdsaGenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := marshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &ECDSASigner{priv: k, pubPEM: string(pemBytes)}, nil
}

func (s *ECDSASigner) Sign(payload []byte) ([]byte, error) {
	h := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, s.priv, h[:])
}
func (s *ECDSASigner) Verify(payload, signature []byte) bool {
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(&s.priv.PublicKey, h[:], signature)
}
func (s *ECDSASigner) PublicPEM() string     { return s.pubPEM }
func (s *ECDSASigner) AlgorithmName() string { return "ECC" }

var _ domain.Signer = (*ECDSASigner)(nil)
