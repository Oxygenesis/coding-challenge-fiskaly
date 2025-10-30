package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"

	httpApp "github.com/oxygenesis/signature/internal/app/http"
	"github.com/oxygenesis/signature/internal/crypto"
	"github.com/oxygenesis/signature/internal/domain"
	"github.com/oxygenesis/signature/internal/service"
	"github.com/oxygenesis/signature/internal/storage"
	"github.com/oxygenesis/signature/pkg/id"
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
