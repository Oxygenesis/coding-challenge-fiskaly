package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"

	httpApp "example.com/fiskaly/signature/internal/app/http"
	"example.com/fiskaly/signature/internal/crypto"
	"example.com/fiskaly/signature/internal/domain"
	"example.com/fiskaly/signature/internal/service"
	"example.com/fiskaly/signature/internal/storage"
	"example.com/fiskaly/signature/pkg/id"
)

type factory struct{}

func (factory) NewRSA(bits int) (domain.Signer, error) { return crypto.NewRSASigner(bits) }
func (factory) NewECDSA() (domain.Signer, error)       { return crypto.NewECDSASigner() }

// test-stubbables
var httpStart = httpApp.Start
var osExit = os.Exit

func main() {
	var (
		mode string
		addr string
		test bool
	)
	flag.StringVar(&mode, "mode", "http", "service mode: http")
	flag.StringVar(&addr, "addr", ":8080", "listen address")
	flag.BoolVar(&test, "t", false, "test mode: build server only")
	flag.Parse()

	ctx := context.Background()
	repo := storage.NewMemory()
	svc := service.New(repo, factory{}, id.UUIDv4{})

	var err error
	switch mode {
	case "http":
		err = httpStart(ctx, addr, svc, test)
	default:
		err = errors.New("unsupported mode")
	}

	if err != nil {
		log.Printf("fatal: %v", err)
		osExit(1)
	}
}
