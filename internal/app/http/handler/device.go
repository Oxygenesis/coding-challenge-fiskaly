package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/oxygenesis/signature/internal/domain"
	"github.com/oxygenesis/signature/internal/service"
)

type Device struct{ svc *service.DeviceService }

func NewDevice(svc *service.DeviceService) *Device { return &Device{svc: svc} }

func (h *Device) Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Devices handles /v1/devices
// - GET  -> List
// - POST -> Create
func (h *Device) Devices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.List(w, r)
	case http.MethodPost:
		h.Create(w, r)
	default:
		http.NotFound(w, r)
	}
}

// DeviceOps handles /v1/devices/{id} and /v1/devices/{id}/sign
func (h *Device) DeviceOps(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/devices/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}

	if strings.HasSuffix(rest, "/sign") && r.Method == http.MethodPost {
		id := strings.TrimSuffix(rest, "/sign")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		h.Sign(w, r, id)
		return
	}

	// GET /v1/devices/{id}
	if r.Method == http.MethodGet && !strings.Contains(rest, "/") {
		h.Get(w, r, rest)
		return
	}

	http.NotFound(w, r)
}

func (h *Device) Create(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req struct {
		ID        string `json:"id"`
		Algorithm string `json:"algorithm"`
		Label     string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.ID == "" {
		writeErr(w, http.StatusBadRequest, "id is required")
		return
	}

	dev, err := h.svc.CreateDevice(req.ID, domain.Algorithm(req.Algorithm), req.Label)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrAlreadyExists):
			writeErr(w, http.StatusConflict, err.Error())
		case errors.Is(err, domain.ErrInvalidAlgorithm):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	writeJSON(w, http.StatusCreated, dev)
}

func (h *Device) Get(w http.ResponseWriter, r *http.Request, id string) {
	dev, err := h.svc.GetDevice(id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, dev)
}

func (h *Device) List(w http.ResponseWriter, _ *http.Request) {
	devs, err := h.svc.ListDevices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devs)
}

func (h *Device) Sign(w http.ResponseWriter, r *http.Request, id string) {
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)

	var req struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Let service validate empty data -> ErrInvalidInput => 400 (coverable)
	res, err := h.svc.Sign(id, req.Data)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrNotFound):
			http.NotFound(w, r)
		case errors.Is(err, domain.ErrInvalidInput):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"signature":   res.SignatureB64,
		"signed_data": res.SignedData,
	})
}

// helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
