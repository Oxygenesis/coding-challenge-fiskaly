package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"testing"

	svc "example.com/fiskaly/signature/internal/service"
)

// OK path: Start returns nil, main must not call osExit.
func TestMain_HTTP_OK(t *testing.T) {
	origStart, origExit := httpStart, osExit
	origArgs, origCmd := os.Args, flag.CommandLine
	defer func() {
		httpStart, osExit = origStart, origExit
		os.Args = origArgs
		flag.CommandLine = origCmd
	}()

	// Provide clean flags for main()
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{"app", "-mode=http", "-addr=:0"}

	called := false
	httpStart = func(ctx context.Context, addr string, s *svc.DeviceService, test bool) error {
		if s == nil {
			t.Fatal("nil *service.Service passed to httpStart")
		}
		called = true
		return nil
	}
	osExit = func(int) { t.Fatal("should not exit on OK path") }

	main()
	if !called {
		t.Fatal("expected httpStart to be called")
	}
}

// Error path: Start returns error, main must call osExit(1).
func TestMain_HTTP_Error_Exits(t *testing.T) {
	origStart, origExit := httpStart, osExit
	origArgs, origCmd := os.Args, flag.CommandLine
	defer func() {
		httpStart, osExit = origStart, origExit
		os.Args = origArgs
		flag.CommandLine = origCmd
	}()

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{"app", "-mode=http", "-addr=:0"}

	httpStart = func(context.Context, string, *svc.DeviceService, bool) error {
		return errors.New("boom")
	}
	exited := false
	osExit = func(int) { exited = true }

	main()
	if !exited {
		t.Fatal("expected osExit to be called on error path")
	}
}

func TestMain_UnsupportedMode_Exits(t *testing.T) {
	origStart, origExit := httpStart, osExit
	origArgs, origCmd := os.Args, flag.CommandLine
	defer func() {
		httpStart, osExit = origStart, origExit
		os.Args = origArgs
		flag.CommandLine = origCmd
	}()

	// ensure httpStart is NOT called on unsupported mode
	httpStart = func(context.Context, string, *svc.DeviceService, bool) error {
		t.Fatal("httpStart must not be called for unsupported mode")
		return nil
	}

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{"app", "-mode=grpc"} // any non-"http" triggers default

	exited := false
	osExit = func(int) { exited = true }
	main()
	if !exited {
		t.Fatal("expected osExit to be called for unsupported mode")
	}
}

func TestFactory_Methods_Covered(t *testing.T) {
	f := factory{}
	if s, err := f.NewRSA(1024); err != nil || s.AlgorithmName() != "RSA" {
		t.Fatalf("NewRSA failed: %v", err)
	}
	if s, err := f.NewECDSA(); err != nil || s.AlgorithmName() != "ECC" {
		t.Fatalf("NewECDSA failed: %v", err)
	}
}
