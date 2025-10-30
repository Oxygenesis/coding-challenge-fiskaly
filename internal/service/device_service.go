package service

import (
	"encoding/base64"
	"fmt"

	"github.com/oxygenesis/signature/internal/domain"
	"github.com/oxygenesis/signature/internal/storage"
)

// SignerFactory abstracts signer creation for algorithms.
type SignerFactory interface {
	NewRSA(bits int) (domain.Signer, error)
	NewECDSA() (domain.Signer, error)
}

// IDGenerator abstracts ID creation.
type IDGenerator interface{ New() string }

type DeviceService struct {
	repo    storage.Repository
	signers SignerFactory
	ids     IDGenerator
}

func New(repo storage.Repository, signers SignerFactory, ids IDGenerator) *DeviceService {
	return &DeviceService{repo: repo, signers: signers, ids: ids}
}

// CreateDevice used to create a new device in the memory store.
func (s *DeviceService) CreateDevice(id string, algo domain.Algorithm, label string) (*domain.SignatureDevice, error) {
	if id == "" {
		return nil, domain.ErrInvalidInput
	}

	var signer domain.Signer
	var err error
	switch algo {
	case domain.AlgRSA:
		signer, err = s.signers.NewRSA(2048)
	case domain.AlgECC:
		signer, err = s.signers.NewECDSA()
	default:
		return nil, domain.ErrInvalidAlgorithm
	}

	if err != nil {
		return nil, err
	}

	dev := &domain.SignatureDevice{
		ID: id, Algorithm: algo, Label: label,
		SignatureCounter: 0,
		LastSignatureB64: "",
		PublicKeyPEM:     signer.PublicPEM(),
	}
	if err := s.repo.Create(dev, signer); err != nil {
		return nil, err
	}

	return dev, nil
}

// GetDevice used to get a device from the memory store.
func (s *DeviceService) GetDevice(id string) (*domain.SignatureDevice, error) {
	dev, _, err := s.repo.Get(id)
	return dev, err
}

// ListDevices used to list all devices in the memory store.
func (s *DeviceService) ListDevices() ([]*domain.SignatureDevice, error) {
	return s.repo.List()
}

// Sign used to sign data for a device in the memory store.
func (s *DeviceService) Sign(id string, data string) (*domain.SignatureResult, error) {
	if data == "" {
		return nil, domain.ErrInvalidInput
	}

	var out *domain.SignatureResult
	err := s.repo.Update(id, func(d *domain.SignatureDevice, signer domain.Signer) error {
		var last string
		if d.SignatureCounter == 0 {
			last = base64.StdEncoding.EncodeToString([]byte(d.ID))
		} else {
			last = d.LastSignatureB64
		}

		payload := fmt.Sprintf("%d_%s_%s", d.SignatureCounter, data, last)
		raw, err := signer.Sign([]byte(payload))
		if err != nil {
			return err
		}

		sigB64 := base64.StdEncoding.EncodeToString(raw)
		// commit
		d.LastSignatureB64 = sigB64
		d.SignatureCounter++
		out = &domain.SignatureResult{SignatureB64: sigB64, SignedData: payload}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return out, nil
}
