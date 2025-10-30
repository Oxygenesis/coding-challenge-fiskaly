package storage

import "example.com/fiskaly/signature/internal/domain"

// Repository persists SignatureDevice aggregates.
// Update provides a per-device critical section to support atomic updates.
type Repository interface {
	Create(dev *domain.SignatureDevice, signer domain.Signer) error
	Get(id string) (*domain.SignatureDevice, domain.Signer, error)
	List() ([]*domain.SignatureDevice, error)
	Update(id string, fn func(d *domain.SignatureDevice, signer domain.Signer) error) error
}
