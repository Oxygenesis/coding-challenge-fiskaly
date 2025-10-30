package id

import (
	"crypto/rand"
	"encoding/hex"
)

// Generator creates unique IDs (UUIDv4-like).
type Generator interface {
	New() string
}

type UUIDv4 struct{}

func (UUIDv4) New() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	// Set version (4) and variant (10)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	hexstr := hex.EncodeToString(b[:])
	// 8-4-4-4-12
	return hexstr[0:8] + "-" + hexstr[8:12] + "-" + hexstr[12:16] + "-" + hexstr[16:20] + "-" + hexstr[20:32]
}
