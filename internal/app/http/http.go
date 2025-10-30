package http

import (
	"context"
	"log"
	"net/http"
	"time"

	"example.com/fiskaly/signature/internal/app/http/handler"
	"example.com/fiskaly/signature/internal/app/http/middleware"
	"example.com/fiskaly/signature/internal/service"
)

func defaultListenAndServe(srv *http.Server) error { return srv.ListenAndServe() }

var listenAndServe = defaultListenAndServe

// Start assembles the server. If test==true it returns without serving (for coverage/CI).
func Start(ctx context.Context, addr string, svc *service.DeviceService, test bool) error {
	srv := buildServer(addr, svc)
	if test {
		return nil
	}
	log.Printf("listening on %s", addr)
	return listenAndServe(srv)
}

// buildServer is kept package-private so tests can exercise routes without binding a port.
func buildServer(addr string, svc *service.DeviceService) *http.Server {
	h := handler.NewDevice(svc)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", h.Health)
	mux.HandleFunc("/v1/devices", h.Devices)    // GET -> list, POST -> create
	mux.HandleFunc("/v1/devices/", h.DeviceOps) // GET -> get by id, POST + /sign -> sign

	root := middleware.Recovery(mux)

	return &http.Server{
		Addr:              addr,
		Handler:           root,
		ReadHeaderTimeout: 5 * time.Second,
	}
}
