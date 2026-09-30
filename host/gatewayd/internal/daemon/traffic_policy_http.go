package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const maxTrafficPolicyBody = 256 << 10

type trafficPolicyApplyRequest struct {
	ExpectedRevision uint64               `json:"expected_revision"`
	Policy           trafficpolicy.Policy `json:"policy"`
}

type trafficPolicyRollbackRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

func (m *TrafficPolicyManager) Serve(ctx context.Context, socketPath, groupName string) error {
	groupID, err := prepareTrafficPolicySocketDirectory(socketPath, groupName)
	if err != nil {
		return err
	}
	if err := removeSocket(socketPath); err != nil {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if err := os.Chown(socketPath, 0, groupID); err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		return err
	}
	server := &http.Server{
		Handler:           m.Handler(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go m.reconcileLoop(ctx)
	go m.ownershipLoop(ctx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		_ = listener.Close()
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func prepareTrafficPolicySocketDirectory(socketPath, groupName string) (int, error) {
	socketPath = strings.TrimSpace(socketPath)
	groupName = strings.TrimSpace(groupName)
	if socketPath == "" || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || filepath.Dir(socketPath) == "/" {
		return 0, errors.New("traffic policy socket path must be a clean absolute path below a directory")
	}
	if groupName == "" {
		return 0, errors.New("traffic policy socket group is required")
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, fmt.Errorf("look up traffic policy socket group: %w", err)
	}
	groupID, err := strconv.ParseUint(group.Gid, 10, 31)
	if err != nil {
		return 0, errors.New("traffic policy socket group ID is invalid")
	}
	directory := filepath.Dir(socketPath)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return 0, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("traffic policy socket directory is unsafe")
	}
	if err := os.Chown(directory, 0, int(groupID)); err != nil {
		return 0, err
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		return 0, err
	}
	return int(groupID), nil
}

func (m *TrafficPolicyManager) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/policy", m.handlePolicy)
	mux.HandleFunc("GET /v1/catalog", m.handleCatalog)
	mux.HandleFunc("POST /v1/preview", m.handlePreview)
	mux.HandleFunc("POST /v1/apply", m.handleApply)
	mux.HandleFunc("POST /v1/rollback", m.handleRollback)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.RawQuery != "" {
			writeTrafficError(w, http.StatusBadRequest, "invalid_query")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (m *TrafficPolicyManager) handlePolicy(w http.ResponseWriter, _ *http.Request) {
	document, err := m.PolicyStore.Load()
	if err != nil {
		writeTrafficError(w, http.StatusServiceUnavailable, "policy_unavailable")
		return
	}
	writeTrafficJSON(w, http.StatusOK, document)
}

func (m *TrafficPolicyManager) handleCatalog(w http.ResponseWriter, _ *http.Request) {
	writeTrafficJSON(w, http.StatusOK, trafficpolicy.BuiltinCatalog())
}

func (m *TrafficPolicyManager) handlePreview(w http.ResponseWriter, r *http.Request) {
	var policy trafficpolicy.Policy
	if err := decodeTrafficJSON(w, r, &policy); err != nil {
		writeTrafficError(w, http.StatusBadRequest, "invalid_policy")
		return
	}
	preview, err := m.preview(policy)
	if err != nil {
		writeTrafficError(w, http.StatusBadRequest, "policy_rejected")
		return
	}
	writeTrafficJSON(w, http.StatusOK, preview)
}

func (m *TrafficPolicyManager) handleApply(w http.ResponseWriter, r *http.Request) {
	var request trafficPolicyApplyRequest
	if err := decodeTrafficJSON(w, r, &request); err != nil {
		writeTrafficError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	document, err := m.Apply(r.Context(), request.Policy, request.ExpectedRevision)
	if err != nil {
		status := http.StatusConflict
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "requires") {
			status = http.StatusBadRequest
		}
		writeTrafficError(w, status, "policy_apply_failed")
		return
	}
	writeTrafficJSON(w, http.StatusOK, document)
}

func (m *TrafficPolicyManager) handleRollback(w http.ResponseWriter, r *http.Request) {
	var request trafficPolicyRollbackRequest
	if err := decodeTrafficJSON(w, r, &request); err != nil {
		writeTrafficError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	document, err := m.Rollback(r.Context(), request.ExpectedRevision)
	if err != nil {
		writeTrafficError(w, http.StatusConflict, "policy_rollback_failed")
		return
	}
	writeTrafficJSON(w, http.StatusOK, document)
}

func decodeTrafficJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return errors.New("application/json is required")
	}
	reader := http.MaxBytesReader(w, r.Body, maxTrafficPolicyBody)
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	return nil
}

func writeTrafficJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeTrafficError(w http.ResponseWriter, status int, code string) {
	writeTrafficJSON(w, status, map[string]string{"error": code})
}
