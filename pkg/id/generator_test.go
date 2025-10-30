package id

import "testing"

func TestUUIDv4_New(t *testing.T) {
	g := UUIDv4{}
	m := map[string]struct{}{}
	for i := 0; i < 50; i++ {
		id := g.New()
		if id == "" { t.Fatal("empty id") }
		if _, ok := m[id]; ok { t.Fatalf("duplicate id: %s", id) }
		m[id] = struct{}{}
	}
}
