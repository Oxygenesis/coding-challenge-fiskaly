package domain

import (
	"encoding/base64"
	"testing"
)

func TestInitialLastSignature(t *testing.T) {
	id := "dev-123"
	got := InitialLastSignature(id)
	want := base64.StdEncoding.EncodeToString([]byte(id))
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
