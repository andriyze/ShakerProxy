package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	api "shakerproxy.dev/shakerproxy/apps/control-api/internal/server"
	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/capabilityregistry"
	"shakerproxy.dev/shakerproxy/internal/casework"
	"shakerproxy.dev/shakerproxy/internal/forwarder"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/recoveryobjectives"
	"shakerproxy.dev/shakerproxy/internal/savedview"
	"shakerproxy.dev/shakerproxy/internal/secretfile"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "-healthcheck" {
		request, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
		request.Host = "localhost:8443"
		client := http.Client{Timeout: 2 * time.Second}
		response, err := client.Do(request)
		if err != nil || response.StatusCode != http.StatusOK {
			fmt.Fprintln(os.Stderr, "control API health check failed")
			os.Exit(1)
		}
		response.Body.Close()
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	registryRoot := envOr("SHAKERPROXY_REGISTRY_ROOT", "/usr/share/shakerproxy")
	capabilities, err := capabilityregistry.LoadRuntime(registryRoot)
	if err != nil {
		logger.Error("capability registry rejected", "error", err)
		os.Exit(1)
	}
	recoveryObjectives, err := recoveryobjectives.LoadRuntime(registryRoot)
	if err != nil {
		logger.Error("recovery objective registry rejected", "error", err)
		os.Exit(1)
	}
	dataDirectory := envOr("SHAKERPROXY_DATA_DIR", "/var/lib/shakerproxy/control-api")
	inventoryStore := &inventory.Store{
		Path:    envOr("SHAKERPROXY_INVENTORY_PATH", "/var/lib/shakerproxy/inventory/inventory.json"),
		Vendors: &inventory.VendorRegistry{Directory: envOr("SHAKERPROXY_IEEE_REGISTRY_DIR", "/var/lib/shakerproxy/ieee")},
	}
	if err := inventory.MigrateLegacyStore(inventoryStore, &inventory.Store{Path: dataDirectory + "/inventory.json"}); err != nil {
		logger.Error("device inventory migration failed", "error", err)
		os.Exit(1)
	}
	queryToken, err := secretfile.LoadToken(envOr("SHAKERPROXY_EVENT_QUERY_TOKEN_FILE", "/run/secrets/event_query_token"))
	if err != nil {
		logger.Error("event query token unavailable", "error", err)
		os.Exit(1)
	}
	eventReader, err := ingest.NewQueryClient(envOr("SHAKERPROXY_INGEST_QUERY_URL", "http://ingestd:8081"), queryToken, nil)
	if err != nil {
		logger.Error("event query client configuration rejected", "error", err)
		os.Exit(1)
	}
	eventDeletionToken, err := secretfile.LoadToken(envOr("SHAKERPROXY_EVENT_DELETION_TOKEN_FILE", "/run/secrets/event_deletion_token"))
	if err != nil {
		logger.Error("event deletion token unavailable", "error", err)
		os.Exit(1)
	}
	eventDeletions, err := ingest.NewDeletionClient(envOr("SHAKERPROXY_INGEST_QUERY_URL", "http://ingestd:8081"), eventDeletionToken, nil)
	if err != nil {
		logger.Error("event deletion client configuration rejected", "error", err)
		os.Exit(1)
	}
	zeekCheckpointDeletions, err := analyzer.NewMaintenanceClient(envOr("SHAKERPROXY_ZEEK_MAINTENANCE_URL", "http://zeek:8082"), eventDeletionToken, nil)
	if err != nil {
		logger.Error("Zeek checkpoint deletion client configuration rejected", "error", err)
		os.Exit(1)
	}
	suricataCheckpointDeletions, err := analyzer.NewMaintenanceClient(envOr("SHAKERPROXY_SURICATA_MAINTENANCE_URL", "http://suricata:8082"), eventDeletionToken, nil)
	if err != nil {
		logger.Error("Suricata checkpoint deletion client configuration rejected", "error", err)
		os.Exit(1)
	}
	savedViewToken, err := secretfile.LoadToken(envOr("SHAKERPROXY_SAVED_VIEW_TOKEN_FILE", "/run/secrets/saved_view_token"))
	if err != nil {
		logger.Error("saved view storage token unavailable", "error", err)
		os.Exit(1)
	}
	savedViews, err := savedview.NewClient(envOr("SHAKERPROXY_INGEST_QUERY_URL", "http://ingestd:8081"), savedViewToken, nil)
	if err != nil {
		logger.Error("saved view client configuration rejected", "error", err)
		os.Exit(1)
	}
	config := api.Config{
		Store:         api.NewStore(dataDirectory, envOr("SHAKERPROXY_SETUP_TOKEN_DIGEST_FILE", "/run/secrets/setup_token_sha256")),
		GatewaySocket: envOr("SHAKERPROXY_GATEWAY_SOCKET", "/run/shakerproxy/gatewayd.sock"),
		AllowedHosts:  strings.Split(envOr("SHAKERPROXY_ALLOWED_HOSTS", "localhost:8443,127.0.0.1:8443"), ","), Logger: logger,
		Inventory:                   inventoryStore,
		KeaLeasePath:                envOr("SHAKERPROXY_KEA_DHCP4_LEASE_FILE", "/var/lib/shakerproxy/kea/kea-leases4.csv"),
		EventReader:                 eventReader,
		LiveEventReader:             eventReader,
		IngestStatus:                eventReader,
		EventSnapshots:              eventReader,
		SavedViews:                  savedViews,
		CaptureEventDeletions:       eventDeletions,
		EventSelectionDeletions:     eventDeletions,
		ZeekCheckpointDeletions:     zeekCheckpointDeletions,
		SuricataCheckpointDeletions: suricataCheckpointDeletions,
		Capabilities:                capabilities,
		RecoveryObjectives:          recoveryObjectives,
		ManagementCACertPath:        envOr("SHAKERPROXY_MANAGEMENT_CA_PATH", "/var/lib/shakerproxy/public/management-ca.crt"),
		ManagementPKIStatusPath:     envOr("SHAKERPROXY_MANAGEMENT_PKI_STATUS_PATH", "/var/lib/shakerproxy/public/management-pki.json"),
		Cases:                       &casework.Store{Path: dataDirectory + "/cases.json"},
		APITokens:                   &apitoken.Store{Path: dataDirectory + "/api-tokens.json"},
		Forwarders:                  &forwarder.Manager{Root: envOr("SHAKERPROXY_FORWARDER_ROOT", "/var/lib/shakerproxy/forwarders")},
		SyslogCollectorConfigPath:   envOr("SHAKERPROXY_SYSLOG_CONFIG_FILE", "/var/lib/shakerproxy/syslog-collector/config.json"),
		SyslogCollectorStatusPath:   envOr("SHAKERPROXY_SYSLOG_STATUS_FILE", "/var/lib/shakerproxy/syslog-collector/status.json"),
		OpenAPIPath:                 filepath.Join(registryRoot, "schemas", "api", "openapi.yaml"),
		AdminResetRequestPath:       envOr("SHAKERPROXY_ADMIN_RESET_REQUEST", filepath.Join(dataDirectory, "admin-reset.request")),
	}
	controlServer := api.New(config)
	coreHandler := controlServer.Handler()
	agentDeviceHandler := controlServer.AgentDeviceHandler()
	agentHTTPActivityHandler := controlServer.AgentHTTPActivityHandler()
	agentSystemOverviewHandler := controlServer.AgentSystemOverviewHandler()
	agentConnectionHandler := controlServer.AgentConnectionHandler()
	testLabHandler := controlServer.TestLabHandler()
	rootHandler := http.NewServeMux()
	rootHandler.Handle("GET /api/v1/events/{recordID}", controlServer.EventDetailOrFallback(coreHandler))
	rootHandler.Handle("/api/v1/http-content-policy", controlServer.HTTPContentPolicyHandler(envOr("SHAKERPROXY_HTTP_CONTENT_POLICY_PATH", "/var/lib/shakerproxy/content-policy/policy.json")))
	rootHandler.Handle("/api/v1/agent/devices", agentDeviceHandler)
	rootHandler.Handle("/api/v1/agent/devices/", agentDeviceHandler)
	rootHandler.Handle("GET /api/v1/agent/http-activity", agentHTTPActivityHandler)
	rootHandler.Handle("GET /api/v1/agent/system-overview", agentSystemOverviewHandler)
	rootHandler.Handle("/api/v1/agent-connections/", agentConnectionHandler)
	rootHandler.Handle("/api/v1/self-test/", testLabHandler)
	coverageHandler := controlServer.CoverageHandler()
	rootHandler.Handle("/api/v1/coverage", coverageHandler)
	rootHandler.Handle("/api/v1/coverage/", coverageHandler)
	rootHandler.Handle("/", coreHandler)
	httpServer := &http.Server{Addr: envOr("SHAKERPROXY_API_BIND", "127.0.0.1:8080"), Handler: rootHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 110 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var workers sync.WaitGroup
	for _, worker := range []func(context.Context){
		func(ctx context.Context) { controlServer.RunInventorySync(ctx, 5*time.Second) },
		func(ctx context.Context) { controlServer.RunCaptureDeletionRecovery(ctx, 15*time.Second) },
		controlServer.RunDeviceTrafficDeletionRecovery,
		func(ctx context.Context) { controlServer.RunCaptureRetentionScheduler(ctx, 30*time.Second) },
		func(ctx context.Context) { controlServer.RunAdminResetWatcher(ctx, 5*time.Second) },
	} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			worker(ctx)
		}()
	}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- httpServer.ListenAndServe() }()
	logger.Info("control API starting", "bind", httpServer.Addr)
	select {
	case err := <-serverErrors:
		stop()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("control API stopped", "error", err)
			os.Exit(1)
		}
		return
	case <-ctx.Done():
	}
	// Graceful shutdown: stop accepting connections, let in-flight requests
	// finish, then wait for background workers to observe cancellation. The
	// bound stays below the default container stop grace period.
	logger.Info("control API shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("control API shutdown did not drain every request", "error", err)
	}
	if err := <-serverErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Warn("control API listener stopped with an error", "error", err)
	}
	finished := make(chan struct{})
	go func() {
		workers.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-shutdownCtx.Done():
		logger.Warn("control API background workers did not stop before the shutdown deadline")
	}
	logger.Info("control API stopped")
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
