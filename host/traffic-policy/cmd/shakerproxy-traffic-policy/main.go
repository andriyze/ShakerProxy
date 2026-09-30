package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const version = "0.1.0-dev.1"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	socketPath := envOr("SHAKERPROXY_TRAFFIC_POLICY_SOCKET", "/run/shakerproxy-traffic-policy/policy.sock")
	stateRoot := envOr("SHAKERPROXY_TRAFFIC_POLICY_STATE_ROOT", "/var/lib/shakerproxy/traffic-policy")
	proxyPolicyPath := envOr("SHAKERPROXY_MITM_POLICY_PATH", "/var/lib/shakerproxy/mitmproxy/policy.json")
	manager := &trafficpolicy.Manager{
		StateRoot:            stateRoot,
		ProxyPolicyPath:      proxyPolicyPath,
		GatewayStatePath:     envOr("SHAKERPROXY_GATEWAY_STATE_PATH", "/var/lib/shakerproxy/gatewayd/state.json"),
		CoordinationLockPath: envOr("SHAKERPROXY_TRAFFIC_POLICY_LOCK_PATH", "/run/lock/shakerproxy/traffic-policy.lock"),
		NFT:                  trafficpolicy.CommandNFT{Binary: envOr("SHAKERPROXY_NFT_BINARY", "/usr/sbin/nft")},
		Probe:                trafficpolicy.TCPMITMProbe{Host: envOr("SHAKERPROXY_MITM_HOST", "127.0.0.1")},
		LocalPolicyCleaner:   trafficpolicy.CommandLocalPolicyCleaner{Binary: envOr("SHAKERPROXY_IPTABLES_BINARY", "/usr/sbin/iptables")},
	}
	if _, err := manager.InitializeEmergencyBypass(ctx); err != nil {
		logger.Warn("initial emergency bypass reconciliation failed; enforcement remains fail-open", "error", err)
	}
	go watchEmergencyBypass(ctx, manager, logger)

	listener, err := listenUnix(socketPath)
	if err != nil {
		fatal(logger, "traffic policy control socket failed", err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler:           policyServer{Manager: manager, Logger: logger}.Handler(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       45 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()

	logger.Info("traffic policy service ready", "socket", socketPath, "version", version, "owned_nft_table", trafficpolicy.OwnedNFTTable)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(logger, "traffic policy service stopped", err)
	}
}

func watchEmergencyBypass(ctx context.Context, manager *trafficpolicy.Manager, logger *slog.Logger) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastError := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			enabled, err := manager.ReconcileEmergencyBypass(ctx)
			if err != nil {
				if message := err.Error(); message != lastError {
					logger.Error("emergency bypass reconciliation failed", "error", err)
					lastError = message
				}
				continue
			}
			if lastError != "" {
				logger.Info("emergency bypass reconciliation recovered", "enabled", enabled)
				lastError = ""
			}
		}
	}
}

type policyServer struct {
	Manager *trafficpolicy.Manager
	Logger  *slog.Logger
}

func (s policyServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("POST /v1/preview", s.preview)
	mux.HandleFunc("POST /v1/apply", s.apply)
	mux.HandleFunc("POST /v1/rollback", s.rollback)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.RawQuery != "" {
			writeError(w, http.StatusBadRequest, "invalid_query")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s policyServer) status(w http.ResponseWriter, _ *http.Request) {
	status, err := s.Manager.Status()
	if err != nil {
		s.failure(w, "status", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "shakerproxy-traffic-policy",
		"version": version,
		"status":  status,
	})
}

func (s policyServer) preview(w http.ResponseWriter, r *http.Request) {
	var request trafficpolicy.ApplyRequest
	if err := decodeJSON(w, r, &request, 512<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	preview, err := s.Manager.Preview(ctx, request)
	if err != nil {
		writeError(w, http.StatusBadRequest, "policy_rejected")
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s policyServer) apply(w http.ResponseWriter, r *http.Request) {
	var request trafficpolicy.ApplyRequest
	if err := decodeJSON(w, r, &request, 512<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if current, err := s.Manager.Status(); err == nil && current.PolicyID == request.PolicyID && current.Revision == request.Revision && current.Digest == request.Digest && current.LastError == "" {
		writeJSON(w, http.StatusOK, map[string]any{"applied": true, "idempotent": true, "status": current})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	status, err := s.Manager.Apply(ctx, request)
	if err != nil {
		s.Logger.Error("traffic policy apply failed", "policy_id", request.PolicyID, "revision", request.Revision, "error", err)
		writeJSON(w, http.StatusConflict, map[string]any{"error": "policy_apply_failed", "status": status})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": true, "idempotent": false, "status": status})
}

func (s policyServer) rollback(w http.ResponseWriter, r *http.Request) {
	var request trafficpolicy.RollbackRequest
	if err := decodeJSON(w, r, &request, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	status, err := s.Manager.Rollback(ctx, request)
	if err != nil {
		s.Logger.Error("traffic policy rollback failed", "error", err)
		writeJSON(w, http.StatusConflict, map[string]any{"error": "policy_rollback_failed", "status": status})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rolled_back": true, "status": status})
}

func (s policyServer) failure(w http.ResponseWriter, operation string, err error) {
	s.Logger.Error("traffic policy API failed", "operation", operation, "error", err)
	writeError(w, http.StatusInternalServerError, "internal_error")
}

func listenUnix(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("traffic policy socket path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace a non-socket traffic policy path")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any, maximum int64) error {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return errors.New("JSON content type is required")
	}
	reader := http.MaxBytesReader(w, r.Body, maximum)
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func fatal(logger *slog.Logger, message string, err error) {
	if err == nil {
		logger.Error(message)
	} else {
		logger.Error(message, "error", err)
	}
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
