package domain

import "encoding/base64"

type Algorithm string

const (
	AlgRSA Algorithm = "RSA"
	AlgECC Algorithm = "ECC"
)

type SignatureDevice struct {
	ID               string    `json:"id"`
	Algorithm        Algorithm `json:"algorithm"`
	Label            string    `json:"label,omitempty"`
	SignatureCounter uint64    `json:"signature_counter"`
	LastSignatureB64 string    `json:"last_signature_base64"`
	PublicKeyPEM     string    `json:"public_key_pem"`
}

// InitialLastSignature returns base64(deviceID) for the base case.
func InitialLastSignature(id string) string {
	return base64.StdEncoding.EncodeToString([]byte(id))
}

type SignatureResult struct {
	SignatureB64 string
	SignedData   string
}
