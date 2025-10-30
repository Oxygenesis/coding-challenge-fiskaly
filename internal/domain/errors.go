package domain

import "errors"

var (
	ErrNotFound         = errors.New("device not found")
	ErrAlreadyExists    = errors.New("device already exists")
	ErrInvalidAlgorithm = errors.New("invalid algorithm")
	ErrInvalidInput     = errors.New("invalid input")
)
