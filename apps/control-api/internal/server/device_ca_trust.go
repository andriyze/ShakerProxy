package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/devicereport"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

type caTrustRequest struct {
	State string `json:"state"`
}

type caTrustResponse struct {
	Schema    int       `json:"schema"`
	DeviceID  string    `json:"device_id"`
	CATrust   string    `json:"ca_trust"`
	UpdatedAt time.Time `json:"updated_at"`
}

// setDeviceCATrust records whether the ShakerProxy CA is installed on a device.
// Reports use it to tell expected decryption (CA installed) from a device
// that accepts untrusted certificates (CA not installed). Changes are
// audited in the device audit log. Administrator sessions and lab:write
// tokens may call it; no password prompt is required.
func (s *Server) setDeviceCATrust(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request caTrustRequest
	if err := decodeJSONBounded(r, &request, 1<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", `Send JSON like {"state":"NOT_INSTALLED"} with Content-Type: application/json.`)
		return
	}
	state := strings.ToUpper(strings.TrimSpace(request.State))
	if !devicereport.ValidCATrust(state) {
		writeError(w, http.StatusBadRequest, "invalid_ca_trust", "State must be INSTALLED, NOT_INSTALLED, or UNKNOWN.")
		return
	}
	device, err := s.resolveDeviceRef(r.Context(), r.PathValue("deviceID"))
	if err != nil {
		writeDeviceRefError(w, err)
		return
	}
	if device.CATrustState() == state {
		writeJSON(w, http.StatusOK, caTrustResponse{Schema: 1, DeviceID: device.ID, CATrust: state, UpdatedAt: time.Now().UTC().Truncate(time.Second)})
		return
	}
	operationID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if operationID == "" {
		operationID, err = newCATrustOperationID()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "Could not record the change. Try again.")
			return
		}
	} else if !deviceinventory.ValidOperationID(operationID) {
		writeError(w, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must be 16-128 letters, digits, hyphens, or underscores.")
		return
	}
	actor := sessionUsername(r.Context())
	if actor == "" {
		actor = "admin"
	}
	result, err := s.inventory.SetCATrust(device.ID, actor, operationID, state)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			writeError(w, http.StatusNotFound, "device_not_found", "The device was removed or merged. Run `shakerproxy devices` or open Devices.")
		case errors.Is(err, deviceinventory.ErrOperationConflict):
			writeError(w, http.StatusConflict, "idempotency_conflict", "This Idempotency-Key was already used for a different change. Retry without it.")
		case errors.Is(err, deviceinventory.ErrMutationRejected):
			writeError(w, http.StatusConflict, "device_mutation_rejected", "The CA trust state could not be changed. Reload the device and try again.")
		default:
			writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "The change could not be saved. Try again, or check System → Status.")
		}
		return
	}
	updated := device
	if len(result.Devices) == 1 {
		updated = result.Devices[0]
	}
	updatedAt := result.Audit.OccurredAt
	if result.Unchanged || updatedAt.IsZero() {
		updatedAt = time.Now().UTC().Truncate(time.Second)
	}
	s.logger.Info("device CA trust updated", "username", actor, "device_id", device.ID, "ca_trust", updated.CATrustState(), "audit_id", result.Audit.ID, "replayed", result.Replayed)
	writeJSON(w, http.StatusOK, caTrustResponse{Schema: 1, DeviceID: device.ID, CATrust: updated.CATrustState(), UpdatedAt: updatedAt})
}

func newCATrustOperationID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "ca-trust-" + hex.EncodeToString(raw), nil
}
