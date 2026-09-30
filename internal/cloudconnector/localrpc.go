package cloudconnector

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const MaxLocalEnrollmentBytes = 16 << 10

type LocalEnrollmentRequest struct {
	CloudURL string `json:"cloud_url"`
	Token    string `json:"token"`
	Name     string `json:"name"`
}

type LocalServer struct {
	Client          Client
	SoftwareVersion string
	MetadataQueue   *MetadataQueue
	DeviceRuntime   *DeviceRuntimeStore
	ProtocolRollup  *ProtocolRollup
}

func (s LocalServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.HandleFunc("GET /v1/metadata/status", s.metadataStatus)
	mux.HandleFunc("POST /v1/metadata/enqueue", s.enqueueMetadata)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func (s LocalServer) status(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeLocalError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	state, err := s.Client.LoadState()
	if errors.Is(err, os.ErrNotExist) {
		writeLocalJSON(w, http.StatusOK, map[string]any{"enrolled": false, "protocol_version": ProtocolVersion, "software_version": s.SoftwareVersion})
		return
	}
	if err != nil {
		writeLocalError(w, http.StatusInternalServerError, "state_unavailable")
		return
	}
	expiresAt, err := s.Client.currentCertificateExpiry()
	if err != nil {
		writeLocalError(w, http.StatusInternalServerError, "identity_unavailable")
		return
	}
	pendingActivation := false
	if _, err := os.Stat(filepath.Join(s.Client.Root, pendingIdentityFile)); err == nil {
		pendingActivation = true
	} else if !errors.Is(err, os.ErrNotExist) {
		writeLocalError(w, http.StatusInternalServerError, "identity_unavailable")
		return
	}
	ledgerState := "OK"
	ledgerEntries := 0
	inflightJobs := 0
	if ledger, err := s.Client.loadJobLedger(); err != nil {
		ledgerState = "ERROR"
	} else {
		ledgerEntries = len(ledger.Entries)
		for _, entry := range ledger.Entries {
			if !terminalJobStatus(entry.State) {
				inflightJobs++
			}
		}
	}
	writeLocalJSON(w, http.StatusOK, map[string]any{
		"enrolled":                       true,
		"sensor_id":                      state.SensorID,
		"organization_id":                state.OrganizationID,
		"cloud_url":                      state.CloudURL,
		"certificate_expires_at":         expiresAt,
		"pending_certificate_activation": pendingActivation,
		"job_ledger_state":               ledgerState,
		"job_ledger_entries":             ledgerEntries,
		"inflight_jobs":                  inflightJobs,
		"protocol_version":               ProtocolVersion,
		"software_version":               s.SoftwareVersion,
		"device_runtime":                 deviceRuntimeSummary(s.DeviceRuntime),
	})
}

func (s LocalServer) enroll(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeLocalError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeLocalError(w, http.StatusUnsupportedMediaType, "json_required")
		return
	}
	reader := http.MaxBytesReader(w, r.Body, MaxLocalEnrollmentBytes)
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var request LocalEnrollmentRequest
	if err := decoder.Decode(&request); err != nil {
		writeLocalError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeLocalError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	state, err := s.Client.Enroll(r.Context(), request.CloudURL, request.Token, request.Name, s.SoftwareVersion)
	if err != nil {
		writeLocalError(w, http.StatusBadRequest, "enrollment_rejected")
		return
	}
	writeLocalJSON(w, http.StatusCreated, map[string]any{
		"enrolled":               true,
		"sensor_id":              state.SensorID,
		"organization_id":        state.OrganizationID,
		"certificate_expires_at": state.CertificateEnds,
	})
}

func writeLocalJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeLocalError(w http.ResponseWriter, status int, code string) {
	writeLocalJSON(w, status, map[string]string{"error": code})
}
