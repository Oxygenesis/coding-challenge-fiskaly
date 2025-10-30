package storage

import (
	"sync"

	"github.com/oxygenesis/signature/internal/domain"
)

type rec struct {
	mu     sync.Mutex
	dev    *domain.SignatureDevice
	signer domain.Signer
}

type Memory struct {
	mu   sync.RWMutex
	data map[string]*rec
}

func NewMemory() *Memory { return &Memory{data: make(map[string]*rec)} }

// Create used to create a new device in the memory store.
func (m *Memory) Create(dev *domain.SignatureDevice, signer domain.Signer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[dev.ID]; ok {
		return domain.ErrAlreadyExists
	}
	cp := *dev
	m.data[dev.ID] = &rec{dev: &cp, signer: signer}
	return nil
}

// Get used to get a device from the memory store.
func (m *Memory) Get(id string) (*domain.SignatureDevice, domain.Signer, error) {
	m.mu.RLock()
	r, ok := m.data[id]
	m.mu.RUnlock()
	if !ok {
		return nil, nil, domain.ErrNotFound
	}
	cp := *(r.dev)
	return &cp, r.signer, nil
}

// List used to lists all devices in the memory store.
func (m *Memory) List() ([]*domain.SignatureDevice, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*domain.SignatureDevice, 0, len(m.data))
	for _, r := range m.data {
		cp := *(r.dev)
		out = append(out, &cp)
	}
	return out, nil
}

// Update used to update a device in the memory store.
func (m *Memory) Update(id string, fn func(d *domain.SignatureDevice, signer domain.Signer) error) error {
	m.mu.RLock()
	r, ok := m.data[id]
	m.mu.RUnlock()
	if !ok {
		return domain.ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := fn(r.dev, r.signer); err != nil {
		return err
	}
	return nil
}
