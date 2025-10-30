package domain

// Signer is the cryptographic primitive used by devices.
type Signer interface {
	Sign(payload []byte) ([]byte, error)
	Verify(payload, signature []byte) bool
	PublicPEM() string
	AlgorithmName() string // "RSA" or "ECC"
}
