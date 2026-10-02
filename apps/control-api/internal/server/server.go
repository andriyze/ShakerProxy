package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/capabilityregistry"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/casework"
	"shakerproxy.dev/shakerproxy/internal/forwarder"
	"shakerproxy.dev/shakerproxy/internal/gatewayclient"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/managementpki"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/querylang"
	"shakerproxy.dev/shakerproxy/internal/recoveryobjectives"
	"shakerproxy.dev/shakerproxy/internal/savedview"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

type sessionContextKey struct{}
type apiPrincipalContextKey struct{}

type tokenRateWindow struct {
	StartedAt time.Time
	Requests  int
}

type Config struct {
	Store                       *Store
	GatewaySocket               string
	AllowedHosts                []string
	Logger                      *slog.Logger
	Inventory                   *deviceinventory.Store
	KeaLeasePath                string
	EventReader                 ingest.RecentEventReader
	LiveEventReader             ingest.LiveEventReader
	IngestStatus                ingest.StatusReader
	EventSnapshots              ingest.EventQuerySnapshotRepository
	SavedViews                  savedview.Repository
	CaptureEventDeletions       captureEventDeletionService
	EventSelectionDeletions     eventSelectionDeletionService
	ZeekCheckpointDeletions     analyzerCheckpointDeletionService
	SuricataCheckpointDeletions analyzerCheckpointDeletionService
	Capabilities                *capabilityregistry.Bundle
	RecoveryObjectives          *recoveryobjectives.Registry
	ManagementCACertPath        string
	ManagementPKIStatusPath     string
	Cases                       *casework.Store
	APITokens                   *apitoken.Store
	Forwarders                  *forwarder.Manager
	// OpenAPIPath is the packaged OpenAPI document served at /api/v1/openapi.yaml.
	OpenAPIPath string
	// AdminResetRequestPath enables the root-only local administrator reset
	// watcher when non-empty; AdminResetOwnerUID overrides the required owner
	// (root) for tests.
	AdminResetRequestPath string
	AdminResetOwnerUID    *int
}

type analyzerStatusService interface {
	Status(context.Context) (analyzer.HealthSnapshot, error)
}

type Server struct {
	store                       *Store
	gateway                     gatewayclient.Client
	coverage                    coverageState
	allowedHosts                map[string]struct{}
	logger                      *slog.Logger
	inventory                   *deviceinventory.Store
	keaLeasePath                string
	leaseReadProblem            sync.Mutex
	lastLeaseReadProblem        string
	eventReader                 ingest.RecentEventReader
	devicePlatforms             devicePlatformCache
	observedDHCP                observedDHCPState
	liveEventReader             ingest.LiveEventReader
	ingestStatus                ingest.StatusReader
	eventSnapshots              ingest.EventQuerySnapshotRepository
	savedViews                  savedview.Repository
	captureEventDeletions       captureEventDeletionService
	eventSelectionDeletions     eventSelectionDeletionService
	zeekCheckpointDeletions     analyzerCheckpointDeletionService
	suricataCheckpointDeletions analyzerCheckpointDeletionService
	capabilities                *capabilityregistry.Bundle
	recoveryObjectives          *recoveryobjectives.Registry
	managementCACertPath        string
	managementPKIStatusPath     string
	cases                       *casework.Store
	apiTokens                   *apitoken.Store
	forwarders                  *forwarder.Manager
	zeekAnalyzerStatus          analyzerStatusService
	suricataAnalyzerStatus      analyzerStatusService
	nameResolver                *deviceinventory.NameResolver
	sessionsMu                  sync.Mutex
	sessions                    map[string]sessionRecord
	sessionsPath                string
	sessionsSavedAt             time.Time
	clock                       func() time.Time
	authFailuresMu              sync.Mutex
	authFailures                map[string]authFailureCounter
	openAPIPath                 string
	adminResetRequestPath       string
	adminResetOwnerUID          int
	retentionSchedulerMu        sync.Mutex
	retentionSchedulerLastError string
	tokenRateMu                 sync.Mutex
	tokenRates                  map[string]tokenRateWindow
	tokenGlobalRate             tokenRateWindow
	connectivityProbeMu         sync.Mutex
	lastConnectivityProbe       time.Time
	liveSlots                   chan struct{}
	captureDeletionMu           sync.Mutex
	captureRetentionMu          sync.Mutex
	deviceTrafficDeletionMu     sync.Mutex
}

func New(config Config) *Server {
	hosts := make(map[string]struct{}, len(config.AllowedHosts))
	for _, host := range config.AllowedHosts {
		hosts[strings.ToLower(strings.TrimSpace(host))] = struct{}{}
	}
	server := &Server{store: config.Store, gateway: gatewayclient.Client{SocketPath: config.GatewaySocket}, allowedHosts: hosts, logger: config.Logger, inventory: config.Inventory, keaLeasePath: config.KeaLeasePath, eventReader: config.EventReader, liveEventReader: config.LiveEventReader, ingestStatus: config.IngestStatus, eventSnapshots: config.EventSnapshots, savedViews: config.SavedViews, captureEventDeletions: config.CaptureEventDeletions, eventSelectionDeletions: config.EventSelectionDeletions, zeekCheckpointDeletions: config.ZeekCheckpointDeletions, suricataCheckpointDeletions: config.SuricataCheckpointDeletions, capabilities: config.Capabilities, recoveryObjectives: config.RecoveryObjectives, managementCACertPath: config.ManagementCACertPath, managementPKIStatusPath: config.ManagementPKIStatusPath, cases: config.Cases, apiTokens: config.APITokens, forwarders: config.Forwarders, nameResolver: &deviceinventory.NameResolver{Store: config.Inventory}, sessions: make(map[string]sessionRecord), authFailures: make(map[string]authFailureCounter), tokenRates: make(map[string]tokenRateWindow), liveSlots: make(chan struct{}, 16), openAPIPath: config.OpenAPIPath, adminResetRequestPath: config.AdminResetRequestPath}
	if config.Store != nil {
		server.sessionsPath = config.Store.SessionsPath()
		server.loadSessions()
	}
	if server.openAPIPath == "" {
		server.openAPIPath = "/usr/share/shakerproxy/schemas/api/openapi.yaml"
	}
	if config.AdminResetOwnerUID != nil {
		server.adminResetOwnerUID = *config.AdminResetOwnerUID
	}
	if server.managementCACertPath == "" {
		server.managementCACertPath = "/var/lib/shakerproxy/public/management-ca.crt"
	}
	if server.managementPKIStatusPath == "" {
		server.managementPKIStatusPath = "/var/lib/shakerproxy/public/management-pki.json"
	}
	server.zeekAnalyzerStatus, _ = config.ZeekCheckpointDeletions.(analyzerStatusService)
	server.suricataAnalyzerStatus, _ = config.SuricataCheckpointDeletions.(analyzerStatusService)
	return server
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /api/v1/setup/status", s.setupStatus)
	mux.HandleFunc("POST /api/v1/setup/complete", s.completeSetup)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/logout", s.logout)
	mux.HandleFunc("POST /api/v1/auth/recover", s.recoverAdministrator)
	mux.HandleFunc("GET /api/v1", s.apiIndex)
	mux.HandleFunc("GET /api/v1/{$}", s.apiIndex)
	mux.HandleFunc("GET /api/v1/openapi.yaml", s.serveOpenAPI)
	mux.Handle("GET /api/v1/system/status", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.systemStatus)))
	mux.Handle("GET /api/v1/system/diagnostics", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.systemDiagnostics)))
	mux.Handle("GET /api/v1/system/ports", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.servicePortPlan)))
	mux.Handle("POST /api/v1/system/connectivity-probe", s.requireAuth(http.HandlerFunc(s.connectivityProbe)))
	mux.Handle("GET /api/v1/system/management-pki", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.getManagementPKI)))
	mux.Handle("GET /api/v1/system/management-ca.pem", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.downloadManagementCA)))
	mux.Handle("GET /api/v1/interception-ca", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.interceptionCAStatus)))
	mux.Handle("GET /api/v1/interception-ca/download", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.downloadInterceptionCA)))
	mux.Handle("GET /api/v1/analyzers/status", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.analyzerStatus)))
	mux.Handle("GET /api/v1/capabilities", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.getCapabilities)))
	mux.Handle("GET /api/v1/recovery-objectives", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.getRecoveryObjectives)))
	mux.Handle("GET /api/v1/auth/tokens", s.requireAuth(http.HandlerFunc(s.listAPITokens)))
	mux.Handle("POST /api/v1/auth/tokens", s.requireAuth(http.HandlerFunc(s.createAPIToken)))
	mux.Handle("DELETE /api/v1/auth/tokens/{tokenID}", s.requireAuth(http.HandlerFunc(s.revokeAPIToken)))
	mux.Handle("GET /api/v1/metrics", s.requireAPITokenScope(apitoken.ScopeMetricsRead, http.HandlerFunc(s.openMetrics)))
	mux.Handle("GET /api/v1/integrations/forwarders", s.requireAuth(http.HandlerFunc(s.listForwarders)))
	mux.Handle("POST /api/v1/integrations/forwarders", s.requireAuth(http.HandlerFunc(s.createForwarder)))
	mux.Handle("PUT /api/v1/integrations/forwarders/{forwarderID}/enabled", s.requireAuth(http.HandlerFunc(s.setForwarderEnabled)))
	mux.Handle("PATCH /api/v1/integrations/forwarders/{forwarderID}", s.requireAuth(http.HandlerFunc(s.updateForwarder)))
	mux.Handle("DELETE /api/v1/integrations/forwarders/{forwarderID}", s.requireAuth(http.HandlerFunc(s.deleteForwarder)))
	mux.Handle("GET /api/v1/cases", s.requireAuthOrScope(apitoken.ScopeCasesRead, http.HandlerFunc(s.listCases)))
	mux.Handle("POST /api/v1/cases", s.requireAuthOrScope(apitoken.ScopeCasesWrite, http.HandlerFunc(s.createCase)))
	mux.Handle("GET /api/v1/cases/{caseID}", s.requireAuthOrScope(apitoken.ScopeCasesRead, http.HandlerFunc(s.getCase)))
	mux.Handle("PATCH /api/v1/cases/{caseID}", s.requireAuthOrScope(apitoken.ScopeCasesWrite, http.HandlerFunc(s.updateCase)))
	mux.Handle("DELETE /api/v1/cases/{caseID}", s.requireAuth(http.HandlerFunc(s.deleteCase)))
	mux.Handle("POST /api/v1/cases/{caseID}/evidence", s.requireAuthOrScope(apitoken.ScopeCasesWrite, http.HandlerFunc(s.addCaseEvidence)))
	mux.Handle("DELETE /api/v1/cases/{caseID}/evidence/{evidenceID}", s.requireAuthOrScope(apitoken.ScopeCasesWrite, http.HandlerFunc(s.removeCaseEvidence)))
	mux.Handle("PUT /api/v1/cases/{caseID}/status", s.requireAuth(http.HandlerFunc(s.setCaseStatus)))
	mux.Handle("POST /api/v1/cases/{caseID}/hold", s.requireAuth(http.HandlerFunc(s.setCaseHold)))
	mux.Handle("GET /api/v1/preflight", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.preflight)))
	mux.Handle("POST /api/v1/network/validate", s.requireAuth(http.HandlerFunc(s.validateNetworkPlan)))
	mux.Handle("POST /api/v1/network/preview", s.requireAuth(http.HandlerFunc(s.previewNetworkPlan)))
	mux.Handle("POST /api/v1/network/stage", s.requireAuth(http.HandlerFunc(s.stageNetworkPlan)))
	mux.Handle("POST /api/v1/network/staged/{applyID}/rollback", s.requireAuth(http.HandlerFunc(s.rollbackStagedNetworkPlan)))
	mux.Handle("POST /api/v1/network/staged/{applyID}/commit", s.requireAuth(http.HandlerFunc(s.commitNetworkPlan)))
	mux.Handle("POST /api/v1/network/staged/{applyID}/heartbeat", s.requireAuth(http.HandlerFunc(s.signalNetworkHealth)))
	mux.Handle("POST /api/v1/network/staged/{applyID}/confirm", s.requireAuth(http.HandlerFunc(s.confirmNetworkPlan)))
	mux.Handle("POST /api/v1/network/active/revert", s.requireAuth(http.HandlerFunc(s.revertNetworkPlan)))
	mux.Handle("GET /api/v1/traffic-policy", s.requireAuth(http.HandlerFunc(s.getTrafficPolicy)))
	mux.Handle("GET /api/v1/traffic-policy/catalog", s.requireAuth(http.HandlerFunc(s.getTrafficResolverCatalog)))
	mux.Handle("POST /api/v1/traffic-policy/preview", s.requireAuth(http.HandlerFunc(s.previewTrafficPolicy)))
	mux.Handle("PUT /api/v1/traffic-policy", s.requireAuth(http.HandlerFunc(s.applyTrafficPolicy)))
	mux.Handle("GET /api/v1/dns-visibility", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.getDNSVisibility)))
	mux.Handle("GET /api/v1/vpn", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.getVPN)))
	mux.Handle("PUT /api/v1/vpn", s.requireAuth(http.HandlerFunc(s.putVPN)))
	mux.Handle("POST /api/v1/vpn/devices", s.requireAuth(http.HandlerFunc(s.addVPNDevice)))
	mux.Handle("DELETE /api/v1/vpn/devices/{peerID}", s.requireAuth(http.HandlerFunc(s.revokeVPNDevice)))
	mux.Handle("PUT /api/v1/dns-visibility", s.requireLabWrite(http.HandlerFunc(s.putDNSVisibility)))
	mux.Handle("GET /api/v1/wifi-visibility", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.getWiFiVisibility)))
	mux.Handle("PUT /api/v1/wifi-visibility", s.requireLabWrite(http.HandlerFunc(s.putWiFiVisibility)))
	mux.Handle("POST /api/v1/traffic-policy/rollback", s.requireAuth(http.HandlerFunc(s.rollbackTrafficPolicy)))
	mux.Handle("GET /api/v1/captures", s.requireAuthOrScope(apitoken.ScopeCapturesRead, http.HandlerFunc(s.listCaptures)))
	mux.Handle("POST /api/v1/captures", s.requireAuthOrScope(apitoken.ScopeCapturesWrite, http.HandlerFunc(s.startCapture)))
	mux.Handle("PUT /api/v1/captures/lab-recording", s.requireAuthOrScope(apitoken.ScopeCapturesWrite, http.HandlerFunc(s.setLabRecording)))
	mux.Handle("GET /api/v1/captures/{sessionID}", s.requireAuthOrScope(apitoken.ScopeCapturesRead, http.HandlerFunc(s.captureStats)))
	mux.Handle("POST /api/v1/captures/{sessionID}/stop", s.requireAuthOrScope(apitoken.ScopeCapturesWrite, http.HandlerFunc(s.stopCapture)))
	mux.Handle("POST /api/v1/captures/{sessionID}/deletion-preview", s.requireAuth(http.HandlerFunc(s.previewCaptureDeletion)))
	mux.Handle("POST /api/v1/captures/{sessionID}/deletion-jobs", s.requireAuth(http.HandlerFunc(s.deleteCapture)))
	mux.Handle("GET /api/v1/capture-deletion-jobs", s.requireAuth(http.HandlerFunc(s.listCaptureDeletionJobs)))
	mux.Handle("GET /api/v1/capture-deletion-jobs/{jobID}", s.requireAuth(http.HandlerFunc(s.getCaptureDeletionJob)))
	mux.Handle("POST /api/v1/capture-deletion-jobs/{jobID}/retry", s.requireAuth(http.HandlerFunc(s.retryCaptureDeletion)))
	mux.Handle("POST /api/v1/capture-deletion-jobs/{jobID}/supersede", s.requireAuth(http.HandlerFunc(s.supersedeCaptureDeletion)))
	mux.Handle("POST /api/v1/capture-deletion-jobs/{jobID}/cancel", s.requireAuth(http.HandlerFunc(s.cancelCaptureDeletion)))
	mux.Handle("POST /api/v1/capture-retention/preview", s.requireAuth(http.HandlerFunc(s.previewCaptureRetention)))
	mux.Handle("GET /api/v1/capture-retention/policy", s.requireAuth(http.HandlerFunc(s.getCaptureRetentionPolicy)))
	mux.Handle("PUT /api/v1/capture-retention/policy", s.requireAuth(http.HandlerFunc(s.applyCaptureRetentionPolicy)))
	mux.Handle("POST /api/v1/capture-retention/runs", s.requireAuth(http.HandlerFunc(s.startCaptureRetentionRun)))
	mux.Handle("GET /api/v1/capture-retention/runs", s.requireAuth(http.HandlerFunc(s.listCaptureRetentionRuns)))
	mux.Handle("GET /api/v1/capture-retention/scheduler", s.requireAuth(http.HandlerFunc(s.captureRetentionSchedulerStatus)))
	mux.Handle("GET /api/v1/captures/{sessionID}/exports", s.requireAuth(http.HandlerFunc(s.captureExportHistory)))
	mux.Handle("POST /api/v1/captures/{sessionID}/files/{fileName}/export", s.requireAuth(http.HandlerFunc(s.exportCaptureFile)))
	mux.Handle("GET /api/v1/devices", s.requireAuthOrScope(apitoken.ScopeDevicesRead, http.HandlerFunc(s.listDevices)))
	mux.Handle("GET /api/v1/device-aliases/export", s.requireAuth(http.HandlerFunc(s.exportDeviceAliases)))
	mux.Handle("POST /api/v1/device-aliases/import-preview", s.requireAuth(http.HandlerFunc(s.previewDeviceAliasImport)))
	mux.Handle("POST /api/v1/device-aliases/import", s.requireAuth(http.HandlerFunc(s.applyDeviceAliasImport)))
	mux.Handle("GET /api/v1/address-aliases", s.requireAuth(http.HandlerFunc(s.listAddressAliases)))
	mux.Handle("POST /api/v1/address-aliases", s.requireAuth(http.HandlerFunc(s.createAddressAlias)))
	mux.Handle("PUT /api/v1/address-aliases/{aliasID}", s.requireAuth(http.HandlerFunc(s.updateAddressAlias)))
	mux.Handle("DELETE /api/v1/address-aliases/{aliasID}", s.requireAuth(http.HandlerFunc(s.deleteAddressAlias)))
	mux.Handle("GET /api/v1/address-aliases/resolve", s.requireAuth(http.HandlerFunc(s.resolveAddressAlias)))
	mux.Handle("GET /api/v1/device-audit", s.requireAuth(http.HandlerFunc(s.listDeviceAudit)))
	mux.Handle("GET /api/v1/events", s.requireAuthOrScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.listRecentEvents)))
	mux.Handle("GET /api/v1/events/summary", s.requireAuthOrScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.listTrafficSummary)))
	mux.Handle("GET /api/v1/events/query-metadata", s.requireAuthOrScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.eventQueryMetadata)))
	mux.Handle("GET /api/v1/events/query-completions", s.requireAuthOrScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.eventQueryCompletions)))
	mux.Handle("POST /api/v1/event-query-snapshots", s.requireAuth(http.HandlerFunc(s.createEventQuerySnapshot)))
	mux.Handle("GET /api/v1/event-query-snapshots/{snapshotID}", s.requireAuth(http.HandlerFunc(s.getEventQuerySnapshot)))
	mux.Handle("GET /api/v1/saved-views", s.requireAuth(http.HandlerFunc(s.listSavedViews)))
	mux.Handle("POST /api/v1/saved-views", s.requireAuth(http.HandlerFunc(s.createSavedView)))
	mux.Handle("POST /api/v1/saved-views/import", s.requireAuth(http.HandlerFunc(s.importSavedView)))
	mux.Handle("GET /api/v1/saved-views/{viewID}", s.requireAuth(http.HandlerFunc(s.getSavedView)))
	mux.Handle("PUT /api/v1/saved-views/{viewID}", s.requireAuth(http.HandlerFunc(s.updateSavedView)))
	mux.Handle("DELETE /api/v1/saved-views/{viewID}", s.requireAuth(http.HandlerFunc(s.deleteSavedView)))
	mux.Handle("POST /api/v1/saved-views/{viewID}/duplicate", s.requireAuth(http.HandlerFunc(s.duplicateSavedView)))
	mux.Handle("GET /api/v1/saved-views/{viewID}/export", s.requireAuth(http.HandlerFunc(s.exportSavedView)))
	mux.Handle("GET /api/v1/saved-views/{viewID}/history", s.requireAuth(http.HandlerFunc(s.savedViewHistory)))
	mux.Handle("GET /api/v1/events/live", s.requireAuthOrScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.streamLiveEvents)))
	// Plaintext headers and bodies: administrator sessions, or API tokens
	// with the sensitive traffic:content scope (credentials redacted).
	mux.Handle("GET /api/v1/events/{recordID}/http-exchange", s.requireAuthOrScope(apitoken.ScopeTrafficContent, http.HandlerFunc(s.getHTTPExchange)))
	mux.Handle("GET /api/v1/ingest/status", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.getIngestStatus)))
	mux.Handle("GET /api/v1/devices/{deviceID}", s.requireAuthOrScope(apitoken.ScopeDevicesRead, http.HandlerFunc(s.getDevice)))
	mux.Handle("PUT /api/v1/devices/{deviceID}/metadata", s.requireAuth(http.HandlerFunc(s.updateDeviceMetadata)))
	mux.Handle("PUT /api/v1/devices/{deviceID}/alias", s.requireAuth(http.HandlerFunc(s.updateDeviceAlias)))
	mux.Handle("POST /api/v1/devices", s.requireAuth(http.HandlerFunc(s.nameDeviceAddress)))
	mux.Handle("DELETE /api/v1/devices/{deviceID}/pinned-address", s.requireAuth(http.HandlerFunc(s.unpinDeviceAddress)))
	mux.Handle("POST /api/v1/devices/{deviceID}/merge", s.requireAuth(http.HandlerFunc(s.mergeDevice)))
	mux.Handle("POST /api/v1/devices/{deviceID}/split", s.requireAuth(http.HandlerFunc(s.splitDevice)))
	mux.Handle("POST /api/v1/devices/{deviceID}/traffic-deletion-preview", s.requireAuth(http.HandlerFunc(s.previewDeviceTrafficDeletion)))
	mux.Handle("POST /api/v1/devices/{deviceID}/traffic-deletion-jobs", s.requireAuth(http.HandlerFunc(s.createDeviceTrafficDeletionJob)))
	mux.Handle("GET /api/v1/device-traffic-deletion-jobs", s.requireAuth(http.HandlerFunc(s.listDeviceTrafficDeletionJobs)))
	mux.Handle("GET /api/v1/device-traffic-deletion-jobs/{jobID}", s.requireAuth(http.HandlerFunc(s.getDeviceTrafficDeletionJob)))
	mux.Handle("POST /api/v1/device-traffic-deletion-jobs/{jobID}/retry", s.requireAuth(http.HandlerFunc(s.retryDeviceTrafficDeletionJob)))
	mux.Handle("POST /api/v1/device-traffic-deletion-jobs/{jobID}/cancel", s.requireAuth(http.HandlerFunc(s.cancelDeviceTrafficDeletionJob)))
	s.registerProtocolRoutes(mux)
	s.registerDeviceIntelRoutes(mux)
	s.registerLabControlRoutes(mux)
	s.registerAgentEvidenceRoutes(mux)
	return s.wrapMux(mux)
}

func (s *Server) getManagementPKI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "management PKI status does not accept query parameters")
		return
	}
	_, status, err := managementpki.LoadPublic(s.managementCACertPath, s.managementPKIStatusPath)
	if err != nil {
		s.logger.Warn("management PKI status unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "management_pki_unavailable", "management PKI status is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) downloadManagementCA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "management CA download does not accept query parameters")
		return
	}
	certificate, _, err := managementpki.LoadPublic(s.managementCACertPath, s.managementPKIStatusPath)
	if err != nil {
		s.logger.Warn("management CA unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "management_ca_unavailable", "management CA is unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="shakerproxy-management-ca.pem"`)
	w.Header().Set("X-ShakerProxy-Certificate-Purpose", managementpki.Purpose)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(certificate)
}

func (s *Server) getCapabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "capability registry does not accept query parameters")
		return
	}
	if s.capabilities == nil {
		writeError(w, http.StatusServiceUnavailable, "capability_registry_unavailable", "capability registry is not configured")
		return
	}
	writeJSON(w, http.StatusOK, s.capabilities)
}

func (s *Server) getRecoveryObjectives(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "recovery objectives do not accept query parameters")
		return
	}
	if s.recoveryObjectives == nil {
		writeError(w, http.StatusServiceUnavailable, "recovery_objectives_unavailable", "recovery objectives are not configured")
		return
	}
	writeJSON(w, http.StatusOK, s.recoveryObjectives)
}

func (s *Server) getIngestStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.ingestStatus == nil {
		writeError(w, http.StatusServiceUnavailable, "ingest_status_unavailable", "ingestion status is not configured")
		return
	}
	statusContext, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	stats, err := s.ingestStatus.IngestStatus(statusContext)
	if err != nil {
		s.logger.Warn("ingestion status proxy failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "ingest_status_unavailable", "ingestion status is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) listRecentEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := ingest.ParseRecentEventQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	if s.eventReader == nil {
		writeError(w, http.StatusServiceUnavailable, "event_store_unavailable", "normalized event storage is not configured")
		return
	}
	if err := s.resolveEventDeviceSelectors(&query); err != nil {
		if errors.Is(err, deviceinventory.ErrAliasResolutionLimit) {
			writeError(w, http.StatusUnprocessableEntity, "query_too_broad", "device selector query matches too many devices; use device.id to narrow it")
			return
		}
		s.logger.Warn("device selector query resolution failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "device_selectors_unavailable", "device selector search is temporarily unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	page, err := s.eventReader.QueryRecent(queryContext, query)
	if err != nil {
		s.logger.Warn("normalized event query proxy failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "event_store_unavailable", "normalized events are temporarily unavailable")
		return
	}
	page.DeviceLabelsAvailable = s.projectDeviceNames(page.Events)
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) resolveEventDeviceSelectors(query *ingest.RecentEventQuery) error {
	names := querylang.DeviceNameValues(query.Filter)
	tags := querylang.DeviceTagValues(query.Filter)
	if len(names) == 0 && len(tags) == 0 {
		query.DeviceNameResolutions = nil
		query.DeviceTagResolutions = nil
		return nil
	}
	if s.nameResolver == nil {
		return errors.New("device name resolver is unavailable")
	}
	resolvedNames, resolvedTags, err := s.nameResolver.ResolveSelectors(names, tags)
	if err != nil {
		return err
	}
	query.DeviceNameResolutions = resolvedNames
	query.DeviceTagResolutions = resolvedTags
	return nil
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) setupStatus(w http.ResponseWriter, _ *http.Request) {
	configured, err := s.store.IsConfigured()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "state_unavailable", "setup state is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"configured": configured})
}

type setupRequest struct {
	SetupToken                string `json:"setup_token"`
	Username                  string `json:"username"`
	Password                  string `json:"password"`
	AuthorizationAcknowledged bool   `json:"authorization_acknowledged"`
}

func (s *Server) completeSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request setupRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "setup")
		return
	}
	if !request.AuthorizationAcknowledged {
		writeError(w, http.StatusBadRequest, "acknowledgement_required", "authorized-use acknowledgement is required")
		return
	}
	codes, err := s.store.CreateAdmin(request.SetupToken, request.Username, request.Password)
	if err != nil {
		s.logger.Warn("setup rejected", "error", err)
		writeError(w, http.StatusBadRequest, "setup_rejected", err.Error())
		return
	}
	token, session, err := s.newVerifiedSession(request.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "The administrator was created but a session could not be started; sign in with the new password.")
		return
	}
	s.logger.Info("initial administrator created", "username", request.Username)
	response := sessionResponse(token, session, s.now())
	response["recovery_codes"] = codes
	response["warning"] = "Store these recovery codes now; they will not be shown again."
	writeJSON(w, http.StatusCreated, response)
}

func (s *Server) systemStatus(w http.ResponseWriter, r *http.Request) {
	var status gatewayprotocol.Status
	if err := s.gateway.Call(r.Context(), "GetManagedState", gatewayprotocol.EmptyParams{}, &status); err != nil {
		writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "host gateway service is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) systemDiagnostics(w http.ResponseWriter, r *http.Request) {
	var report gatewayprotocol.DiagnosticReport
	if err := s.gateway.Call(r.Context(), "GetDiagnostics", gatewayprotocol.EmptyParams{}, &report); err != nil {
		writeError(w, http.StatusServiceUnavailable, "diagnostics_unavailable", "appliance diagnostics are unavailable")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) preflight(w http.ResponseWriter, r *http.Request) {
	var inspection gatewayprotocol.HostInspection
	if err := s.gateway.Call(r.Context(), "InspectHost", gatewayprotocol.EmptyParams{}, &inspection); err != nil {
		writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "host inspection is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, inspection)
}

func (s *Server) validateNetworkPlan(w http.ResponseWriter, r *http.Request) {
	var plan networkplan.Plan
	if err := decodeJSON(r, &plan); err != nil {
		writeDecodeError(w, err, "network plan")
		return
	}
	var result networkplan.ValidationResult
	params := gatewayprotocol.ValidateNetworkPlanParams{Plan: plan}
	if err := s.gateway.Call(r.Context(), "ValidateNetworkPlan", params, &result); err != nil {
		writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "network plan validation is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) previewNetworkPlan(w http.ResponseWriter, r *http.Request) {
	var plan networkplan.Plan
	if err := decodeJSON(r, &plan); err != nil {
		writeDecodeError(w, err, "network plan")
		return
	}
	var preview networkplan.Preview
	params := gatewayprotocol.PreviewNetworkPlanParams{Plan: plan}
	if err := s.gateway.Call(r.Context(), "PreviewNetworkPlan", params, &preview); err != nil {
		writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "network plan preview is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

type stageNetworkPlanRequest struct {
	Plan             networkplan.Plan `json:"plan"`
	ExpectedPlanHash string           `json:"expected_plan_hash"`
	StageTTLSeconds  int              `json:"stage_ttl_seconds"`
}

func (s *Server) stageNetworkPlan(w http.ResponseWriter, r *http.Request) {
	var request stageNetworkPlanRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "stage")
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	params := gatewayprotocol.StageNetworkPlanParams{Plan: request.Plan, ExpectedPlanHash: request.ExpectedPlanHash, IdempotencyKey: idempotencyKey, StageTTLSeconds: request.StageTTLSeconds}
	var staged networkplan.StagedPlan
	if err := s.gateway.Call(r.Context(), "StageNetworkPlan", params, &staged); err != nil {
		writeError(w, http.StatusConflict, "stage_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, staged)
}

func (s *Server) rollbackStagedNetworkPlan(w http.ResponseWriter, r *http.Request) {
	applyID := r.PathValue("applyID")
	if applyID == "" {
		writeError(w, http.StatusBadRequest, "apply_id_required", "apply ID is required")
		return
	}
	var result map[string]any
	if err := s.gateway.Call(r.Context(), "RollbackNetworkPlan", gatewayprotocol.RollbackNetworkPlanParams{ApplyID: applyID}, &result); err != nil {
		writeError(w, http.StatusConflict, "rollback_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type commitNetworkPlanRequest struct {
	PlanHash              string `json:"plan_hash"`
	Password              string `json:"password"`
	RollbackWindowSeconds int    `json:"rollback_window_seconds"`
}

func (s *Server) commitNetworkPlan(w http.ResponseWriter, r *http.Request) {
	applyID := r.PathValue("applyID")
	var request commitNetworkPlanRequest
	if applyID == "" {
		writeError(w, http.StatusBadRequest, "apply_id_required", "The staged apply ID is required.")
		return
	}
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "network commit")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	params := gatewayprotocol.CommitNetworkPlanParams{ApplyID: applyID, PlanHash: request.PlanHash, IdempotencyKey: idempotencyKey, RollbackWindowSeconds: request.RollbackWindowSeconds}
	var result gatewayprotocol.CommitNetworkPlanResult
	if err := s.gateway.Call(r.Context(), "CommitNetworkPlan", params, &result); err != nil {
		writeError(w, http.StatusConflict, "commit_rejected", err.Error())
		return
	}
	s.logger.Info("network commit accepted", "username", sessionUsername(r.Context()), "apply_id", applyID, "plan_hash", request.PlanHash)
	writeJSON(w, http.StatusAccepted, result)
}

type signalNetworkHealthRequest struct {
	PlanHash string `json:"plan_hash"`
	Token    string `json:"token"`
}

func (s *Server) signalNetworkHealth(w http.ResponseWriter, r *http.Request) {
	applyID := r.PathValue("applyID")
	var request signalNetworkHealthRequest
	if applyID == "" {
		writeError(w, http.StatusBadRequest, "apply_id_required", "The staged apply ID is required.")
		return
	}
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "network heartbeat")
		return
	}
	params := gatewayprotocol.SignalNetworkHealthParams{ApplyID: applyID, PlanHash: request.PlanHash, Token: request.Token}
	var result map[string]any
	if err := s.gateway.Call(r.Context(), "SignalNetworkHealth", params, &result); err != nil {
		writeError(w, http.StatusConflict, "heartbeat_rejected", "management health signal was rejected")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type confirmNetworkPlanRequest struct {
	PlanHash string `json:"plan_hash"`
	Password string `json:"password"`
}

func (s *Server) confirmNetworkPlan(w http.ResponseWriter, r *http.Request) {
	applyID := r.PathValue("applyID")
	var request confirmNetworkPlanRequest
	if applyID == "" {
		writeError(w, http.StatusBadRequest, "apply_id_required", "The staged apply ID is required.")
		return
	}
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "network confirmation")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	params := gatewayprotocol.ConfirmNetworkPlanParams{ApplyID: applyID, PlanHash: request.PlanHash, IdempotencyKey: idempotencyKey}
	var result networkplan.StagedPlan
	if err := s.gateway.Call(r.Context(), "ConfirmNetworkPlan", params, &result); err != nil {
		writeError(w, http.StatusConflict, "confirmation_rejected", err.Error())
		return
	}
	s.logger.Info("network commit confirmed", "username", sessionUsername(r.Context()), "apply_id", applyID, "plan_hash", request.PlanHash)
	writeJSON(w, http.StatusOK, result)
}

type revertNetworkPlanRequest struct {
	Password string `json:"password"`
}

// revertNetworkPlan turns the lab network off: the gateway restores the host
// network as it was before the running plan (like shakerproxy network off).
func (s *Server) revertNetworkPlan(w http.ResponseWriter, r *http.Request) {
	var request revertNetworkPlanRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "network revert")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		return
	}
	var result struct {
		OperatingMode   string `json:"operating_mode"`
		EmergencyBypass bool   `json:"emergency_bypass"`
	}
	if err := s.gateway.Call(r.Context(), "RevertNetworkPlan", gatewayprotocol.EmptyParams{}, &result); err != nil {
		var remote *gatewayclient.RemoteError
		switch {
		case errors.As(err, &remote) && remote.Code == gatewayclient.CodeNetworkApplyUnavailable:
			writeError(w, http.StatusServiceUnavailable, "network_activation_unavailable", "This ShakerProxy install cannot change the network (the gateway runs without network apply). Use an installed appliance.")
		case errors.As(err, &remote) && remote.Code == gatewayclient.CodeNetworkRevertFailed:
			writeError(w, http.StatusConflict, "network_revert_failed", remote.Message)
		case errors.As(err, &remote):
			writeError(w, http.StatusBadGateway, "gateway_error", remote.Message)
		default:
			writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "The host gateway service is unavailable.")
		}
		return
	}
	s.logger.Info("lab network turned off", "username", sessionUsername(r.Context()), "operating_mode", result.OperatingMode, "emergency_bypass", result.EmergencyBypass)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) getTrafficPolicy(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "traffic policy does not accept query parameters")
		return
	}
	var document trafficpolicy.Document
	if err := s.gateway.Call(r.Context(), "GetTrafficPolicy", gatewayprotocol.EmptyParams{}, &document); err != nil {
		writeError(w, http.StatusServiceUnavailable, "traffic_policy_unavailable", "traffic policy is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) getTrafficResolverCatalog(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "resolver catalog does not accept query parameters")
		return
	}
	var catalog trafficpolicy.Catalog
	if err := s.gateway.Call(r.Context(), "GetTrafficResolverCatalog", gatewayprotocol.EmptyParams{}, &catalog); err != nil {
		writeError(w, http.StatusServiceUnavailable, "resolver_catalog_unavailable", "resolver catalog is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, catalog)
}

func (s *Server) previewTrafficPolicy(w http.ResponseWriter, r *http.Request) {
	var policy trafficpolicy.Policy
	if err := decodeJSON(r, &policy); err != nil {
		writeDecodeError(w, err, "traffic policy")
		return
	}
	var preview gatewayprotocol.TrafficPolicyPreview
	if err := s.gateway.Call(r.Context(), "PreviewTrafficPolicy", gatewayprotocol.PreviewTrafficPolicyParams{Policy: policy}, &preview); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "traffic_policy_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

type applyTrafficPolicyRequest struct {
	ExpectedRevision uint64               `json:"expected_revision"`
	Policy           trafficpolicy.Policy `json:"policy"`
	Password         string               `json:"password"`
}

func (s *Server) applyTrafficPolicy(w http.ResponseWriter, r *http.Request) {
	var request applyTrafficPolicyRequest
	if err := decodeJSON(r, &request); err != nil || request.ExpectedRevision == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "request does not match the traffic policy apply schema")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, s.trafficPolicyPasswordPolicy(r, request.Policy)) {
		return
	}
	if request.Policy.DeviceControls == nil {
		// Clients that predate device lab controls send the policy without
		// the field; keep the saved controls instead of silently clearing
		// them. An explicit empty list still clears them.
		var current trafficpolicy.Document
		if err := s.gateway.Call(r.Context(), "GetTrafficPolicy", gatewayprotocol.EmptyParams{}, &current); err == nil {
			request.Policy.DeviceControls = current.Policy.DeviceControls
		}
	}
	request.Policy = s.attachSelectedDeviceIdentity(request.Policy)
	params := gatewayprotocol.ApplyTrafficPolicyParams{ExpectedRevision: request.ExpectedRevision, Policy: request.Policy}
	var document trafficpolicy.Document
	if err := s.gateway.Call(r.Context(), "ApplyTrafficPolicy", params, &document); err != nil {
		writeError(w, http.StatusConflict, "traffic_policy_apply_failed", err.Error())
		return
	}
	s.logger.Info("traffic policy applied", "username", sessionUsername(r.Context()), "revision", document.Policy.Revision, "digest", document.Digest)
	writeJSON(w, http.StatusOK, document)
}

type rollbackTrafficPolicyRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Password         string `json:"password"`
}

func (s *Server) rollbackTrafficPolicy(w http.ResponseWriter, r *http.Request) {
	var request rollbackTrafficPolicyRequest
	if err := decodeJSON(r, &request); err != nil || request.ExpectedRevision == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "request does not match the traffic policy rollback schema")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	var document trafficpolicy.Document
	if err := s.gateway.Call(r.Context(), "RollbackTrafficPolicy", gatewayprotocol.RollbackTrafficPolicyParams{ExpectedRevision: request.ExpectedRevision}, &document); err != nil {
		writeError(w, http.StatusConflict, "traffic_policy_rollback_failed", err.Error())
		return
	}
	s.logger.Info("traffic policy rolled back", "username", sessionUsername(r.Context()), "revision", document.Policy.Revision, "digest", document.Digest)
	writeJSON(w, http.StatusOK, document)
}

type startCaptureRequest struct {
	Name             string       `json:"name"`
	Description      string       `json:"description,omitempty"`
	Mode             capture.Mode `json:"mode"`
	SnapLength       int          `json:"snap_length,omitempty"`
	SegmentSizeMiB   int          `json:"segment_size_mib"`
	SegmentSeconds   int          `json:"segment_seconds"`
	MaxFiles         int          `json:"max_files"`
	StopAfterSeconds int          `json:"stop_after_seconds"`
	RetentionLock    bool         `json:"retention_lock"`
	CaseID           string       `json:"case_id,omitempty"`
	StartReason      string       `json:"start_reason,omitempty"`
}

func (s *Server) listCaptures(w http.ResponseWriter, r *http.Request) {
	var result []capture.View
	if err := s.gateway.Call(r.Context(), "ListCaptures", gatewayprotocol.EmptyParams{}, &result); err != nil {
		writeError(w, http.StatusServiceUnavailable, "capture_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"captures": result})
}

func (s *Server) captureStats(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")
	if !capture.ValidSessionID(sessionID) {
		writeError(w, http.StatusBadRequest, "invalid_capture_id", "capture session ID is invalid")
		return
	}
	var result capture.View
	if err := s.gateway.Call(r.Context(), "GetCaptureStats", gatewayprotocol.GetCaptureStatsParams{SessionID: sessionID}, &result); err != nil {
		writeCaptureGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// writeCaptureGatewayError maps capture lookups to 404 only when the host
// reports that the capture does not exist; profile and transport failures are
// 503 so clients retry instead of assuming the capture is gone.
func writeCaptureGatewayError(w http.ResponseWriter, err error) {
	var remote *gatewayclient.RemoteError
	switch {
	case errors.As(err, &remote) && remote.Code == gatewayclient.CodeCaptureUnavailable:
		writeError(w, http.StatusServiceUnavailable, "capture_unavailable", "Packet capture is not available in this appliance profile.")
	case errors.As(err, &remote) && remote.Code == gatewayclient.CodeCaptureStatus && strings.Contains(remote.Message, "no such file or directory"):
		writeError(w, http.StatusNotFound, "capture_not_found", "No capture has this ID; list captures with GET /api/v1/captures.")
	case errors.As(err, &remote):
		writeError(w, http.StatusServiceUnavailable, "capture_unavailable", "Capture status is temporarily unavailable: "+remote.Message+".")
	default:
		writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "The host gateway service is unavailable; check that shakerproxy-gatewayd is running.")
	}
}

func (s *Server) startCapture(w http.ResponseWriter, r *http.Request) {
	var request startCaptureRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "capture")
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	start := capture.StartRequest{
		Name: request.Name, Description: request.Description, Mode: request.Mode, SnapLength: request.SnapLength,
		SegmentSizeMiB: request.SegmentSizeMiB, SegmentSeconds: request.SegmentSeconds, MaxFiles: request.MaxFiles,
		StopAfterSeconds: request.StopAfterSeconds, RetentionLock: request.RetentionLock, CaseID: request.CaseID,
		StartReason: request.StartReason, IdempotencyKey: idempotencyKey, Administrator: sessionUsername(r.Context()),
	}
	var result capture.View
	if err := s.gateway.Call(r.Context(), "StartCapture", gatewayprotocol.StartCaptureParams{Request: start}, &result); err != nil {
		writeError(w, http.StatusConflict, "capture_rejected", err.Error())
		return
	}
	s.logger.Info("capture start accepted", "username", sessionUsername(r.Context()), "capture_id", result.Session.ID)
	writeJSON(w, http.StatusCreated, result)
}

// setLabRecording turns automatic lab recording on or off. While it is on,
// the gateway records lab traffic whenever a confirmed lab plan routes.
func (s *Server) setLabRecording(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "lab recording")
		return
	}
	if request.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled_required", "Send {\"enabled\": true} or {\"enabled\": false}.")
		return
	}
	var result gatewayprotocol.LabRecordingStatus
	if err := s.gateway.Call(r.Context(), "SetLabRecording", gatewayprotocol.SetLabRecordingParams{Enabled: *request.Enabled}, &result); err != nil {
		writeCaptureGatewayError(w, err)
		return
	}
	s.logger.Info("lab recording setting changed", "username", sessionUsername(r.Context()), "enabled", *request.Enabled)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) stopCapture(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")
	if !capture.ValidSessionID(sessionID) {
		writeError(w, http.StatusBadRequest, "invalid_capture_id", "capture session ID is invalid")
		return
	}
	// Stopping is naturally idempotent (stopping a stopped capture returns its
	// final state), so an Idempotency-Key header is accepted but not required
	// and is not forwarded to the host.
	var request struct{}
	if err := decodeOptionalJSON(r, &request, 1024); err != nil {
		writeDecodeError(w, err, "capture stop")
		return
	}
	var result capture.View
	if err := s.gateway.Call(r.Context(), "StopCapture", gatewayprotocol.StopCaptureParams{SessionID: sessionID}, &result); err != nil {
		writeError(w, http.StatusConflict, "capture_stop_rejected", err.Error())
		return
	}
	s.logger.Info("capture stop accepted", "username", sessionUsername(r.Context()), "capture_id", sessionID)
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) previewCaptureDeletion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sessionID := r.PathValue("sessionID")
	if !capture.ValidSessionID(sessionID) {
		writeError(w, http.StatusBadRequest, "invalid_capture_id", "capture session ID is invalid")
		return
	}
	var request struct{}
	if err := decodeOptionalJSON(r, &request, 1024); err != nil {
		writeDecodeError(w, err, "capture deletion preview")
		return
	}
	if s.captureEventDeletions == nil || s.zeekCheckpointDeletions == nil || s.suricataCheckpointDeletions == nil {
		writeError(w, http.StatusServiceUnavailable, "capture_deletion_backends_unavailable", "capture deletion planning backends are not configured")
		return
	}
	var hostPreview capture.DeletionPreview
	if err := s.gateway.Call(r.Context(), "PreviewCaptureDeletion", gatewayprotocol.PreviewCaptureDeletionParams{SessionID: sessionID}, &hostPreview); err != nil {
		writeError(w, http.StatusConflict, "capture_deletion_preview_rejected", err.Error())
		return
	}
	eventPreview, err := s.captureEventDeletions.Preview(r.Context(), sessionID)
	if err != nil {
		s.logger.Warn("normalized-event deletion preview failed", "capture_id", sessionID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "capture_event_deletion_preview_unavailable", "normalized-event deletion preview is temporarily unavailable")
		return
	}
	zeekPreview, err := s.zeekCheckpointDeletions.Preview(r.Context(), sessionID)
	if err != nil {
		s.logger.Warn("Zeek checkpoint deletion preview failed", "capture_id", sessionID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "analyzer_checkpoint_preview_unavailable", "Zeek checkpoint deletion preview is temporarily unavailable")
		return
	}
	suricataPreview, err := s.suricataCheckpointDeletions.Preview(r.Context(), sessionID)
	if err != nil {
		s.logger.Warn("Suricata checkpoint deletion preview failed", "capture_id", sessionID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "analyzer_checkpoint_preview_unavailable", "Suricata checkpoint deletion preview is temporarily unavailable")
		return
	}
	exports, err := s.store.ListCaptureExports(sessionID)
	if err != nil {
		s.logger.Warn("capture export boundary lookup failed", "capture_id", sessionID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "capture_export_boundary_unavailable", "capture export deletion boundaries are temporarily unavailable")
		return
	}
	result, err := newCoordinatedCaptureDeletionPreview(hostPreview, eventPreview, zeekPreview, suricataPreview, len(exports))
	if err != nil {
		s.logger.Warn("capture deletion backend previews were inconsistent", "capture_id", sessionID, "error", err)
		writeError(w, http.StatusConflict, "capture_deletion_preview_inconsistent", "authoritative deletion previews were inconsistent")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type deleteCaptureRequest struct {
	Password     string                            `json:"password"`
	Preview      coordinatedCaptureDeletionPreview `json:"preview"`
	Confirmation string                            `json:"confirmation"`
}

func (s *Server) deleteCapture(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sessionID := r.PathValue("sessionID")
	var request deleteCaptureRequest
	if !capture.ValidSessionID(sessionID) || decodeJSON(r, &request) != nil || request.Preview.Schema != coordinatedCaptureDeletionSchema || request.Preview.validate() != nil || request.Preview.SessionID != sessionID || request.Confirmation != sessionID || request.Preview.Confirmation != sessionID {
		writeError(w, http.StatusBadRequest, "invalid_request", "request does not match the capture deletion schema")
		return
	}
	if s.captureEventDeletions == nil || s.zeekCheckpointDeletions == nil || s.suricataCheckpointDeletions == nil {
		writeError(w, http.StatusServiceUnavailable, "capture_deletion_backends_unavailable", "capture deletion backends are not configured")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		s.logger.Warn("capture deletion reauthentication failed", "username", username, "capture_id", sessionID)
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	s.captureDeletionMu.Lock()
	defer s.captureDeletionMu.Unlock()
	record, replayed, err := s.store.beginCoordinatedCaptureDeletion(request.Preview, username, idempotencyKey)
	if err != nil {
		switch {
		case errors.Is(err, errCoordinatedCaptureDeletionInvalid):
			writeError(w, http.StatusBadRequest, "invalid_request", "request does not match the capture deletion schema")
		case errors.Is(err, errCoordinatedCaptureDeletionConflict):
			writeError(w, http.StatusConflict, "capture_deletion_idempotency_conflict", errCoordinatedCaptureDeletionConflict.Error())
		case errors.Is(err, errCoordinatedCaptureDeletionExpired):
			writeError(w, http.StatusGone, "capture_deletion_preview_expired", errCoordinatedCaptureDeletionExpired.Error())
		case errors.Is(err, errCaptureDeletionLedgerFull):
			writeError(w, http.StatusInsufficientStorage, "capture_deletion_history_full", "Capture deletion history is full: "+err.Error()+".")
		default:
			s.logger.Error("capture deletion intent persistence failed", "username", username, "capture_id", sessionID, "error", err)
			writeError(w, http.StatusServiceUnavailable, "capture_deletion_store_unavailable", "capture deletion intent could not be persisted")
		}
		return
	}
	if record.Job.State == coordinatedDeletionPending || record.Job.State == coordinatedDeletionRunning {
		ctx, cancel := durableOperationContext(r)
		defer cancel()
		record.Job, err = s.executeCoordinatedCaptureDeletion(ctx, record)
		if err != nil {
			s.logger.Error("capture deletion coordination persistence failed", "username", username, "capture_id", sessionID, "job_id", record.Job.ID, "error", err)
			writeError(w, http.StatusServiceUnavailable, "capture_deletion_coordination_unavailable", "capture deletion coordination could not persist authoritative progress")
			return
		}
	}
	s.logger.Info("capture deletion operation acknowledged", "username", username, "capture_id", sessionID, "job_id", record.Job.ID, "state", record.Job.State, "replayed", replayed)
	writeJSON(w, http.StatusAccepted, record.Job)
}

func (s *Server) listCaptureDeletionJobs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	result, err := s.store.listCoordinatedCaptureDeletionJobs()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "capture_deletion_jobs_unavailable", "capture deletion jobs are temporarily unavailable")
		return
	}
	if result == nil {
		result = []coordinatedCaptureDeletionJob{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": result})
}

func (s *Server) getCaptureDeletionJob(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	jobID := r.PathValue("jobID")
	if !coordinatedCaptureDeletionIDPattern.MatchString(jobID) {
		writeError(w, http.StatusBadRequest, "invalid_capture_deletion_job_id", "capture deletion job ID is invalid")
		return
	}
	job, err := s.store.getCoordinatedCaptureDeletionJob(jobID)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "capture_deletion_job_not_found", "capture deletion job was not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "capture_deletion_job_unavailable", "capture deletion job is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

type retryCaptureDeletionRequest struct {
	Password string `json:"password"`
}

func (s *Server) retryCaptureDeletion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	jobID := r.PathValue("jobID")
	var request retryCaptureDeletionRequest
	if !coordinatedCaptureDeletionIDPattern.MatchString(jobID) || decodeJSON(r, &request) != nil {
		writeError(w, http.StatusBadRequest, "invalid_capture_deletion_retry", "request does not match the capture deletion retry schema")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		s.logger.Warn("capture deletion retry reauthentication failed", "username", username, "job_id", jobID)
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	s.captureDeletionMu.Lock()
	defer s.captureDeletionMu.Unlock()
	record, replayed, err := s.store.beginCoordinatedCaptureDeletionRetry(jobID, idempotencyKey, username)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "capture_deletion_job_not_found", "capture deletion job was not found")
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, errCaptureDeletionRetryInvalid):
			writeError(w, http.StatusBadRequest, "invalid_capture_deletion_retry", errCaptureDeletionRetryInvalid.Error())
		case errors.Is(err, errCaptureDeletionRetryConflict):
			writeError(w, http.StatusConflict, "capture_deletion_retry_idempotency_conflict", errCaptureDeletionRetryConflict.Error())
		case errors.Is(err, errCaptureDeletionRetryLimit):
			writeError(w, http.StatusConflict, "capture_deletion_retry_limit_exceeded", errCaptureDeletionRetryLimit.Error())
		default:
			writeError(w, http.StatusServiceUnavailable, "capture_deletion_retry_store_unavailable", "capture deletion retry intent could not be persisted")
		}
		return
	}
	if replayed {
		s.logger.Info("capture deletion retry replayed", "username", username, "job_id", jobID, "state", record.Job.State)
		writeJSON(w, http.StatusAccepted, record.Job)
		return
	}
	if record.Job.State == coordinatedDeletionPending || record.Job.State == coordinatedDeletionRunning || record.Job.State == coordinatedDeletionPartial || record.Job.State == coordinatedDeletionFailed {
		ctx, cancel := durableOperationContext(r)
		defer cancel()
		job, executeErr := s.executeCoordinatedCaptureDeletion(ctx, record)
		if executeErr != nil {
			s.logger.Error("capture deletion retry coordination failed", "username", username, "job_id", jobID, "error", executeErr)
			writeError(w, http.StatusServiceUnavailable, "capture_deletion_coordination_unavailable", "capture deletion retry could not persist authoritative progress")
			return
		}
		record.Job = job
	}
	finished, err := s.store.finishCoordinatedCaptureDeletionRetry(jobID, idempotencyKey)
	if err != nil {
		s.logger.Error("capture deletion retry completion persistence failed", "username", username, "job_id", jobID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "capture_deletion_retry_store_unavailable", "capture deletion retry result could not be persisted")
		return
	}
	s.logger.Info("capture deletion retry acknowledged", "username", username, "job_id", jobID, "state", finished.Job.State, "replayed", replayed)
	writeJSON(w, http.StatusAccepted, finished.Job)
}

type supersedeCaptureDeletionRequest struct {
	Password     string                            `json:"password"`
	Preview      coordinatedCaptureDeletionPreview `json:"preview"`
	Confirmation string                            `json:"confirmation"`
}

func (s *Server) supersedeCaptureDeletion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	jobID := r.PathValue("jobID")
	var request supersedeCaptureDeletionRequest
	if !coordinatedCaptureDeletionIDPattern.MatchString(jobID) || decodeJSONBounded(r, &request, 4<<20) != nil || request.Preview.Schema != coordinatedCaptureDeletionSchema || request.Preview.validate() != nil || request.Confirmation != request.Preview.SessionID {
		writeError(w, http.StatusBadRequest, "invalid_capture_deletion_supersession", "request does not match the capture deletion supersession schema")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	if s.captureEventDeletions == nil || s.zeekCheckpointDeletions == nil || s.suricataCheckpointDeletions == nil {
		writeError(w, http.StatusServiceUnavailable, "capture_deletion_backends_unavailable", "capture deletion backends are not configured")
		return
	}
	s.captureDeletionMu.Lock()
	defer s.captureDeletionMu.Unlock()
	record, replayed, err := s.store.supersedeCoordinatedCaptureDeletion(jobID, request.Preview, idempotencyKey, username)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "capture_deletion_job_not_found", "capture deletion job was not found")
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, errCaptureDeletionSupersedeInvalid):
			writeError(w, http.StatusConflict, "capture_deletion_supersession_invalid", err.Error())
		case errors.Is(err, errCaptureDeletionSupersedeConflict):
			writeError(w, http.StatusConflict, "capture_deletion_supersession_idempotency_conflict", err.Error())
		case errors.Is(err, errCaptureDeletionSupersedeLimit):
			writeError(w, http.StatusConflict, "capture_deletion_supersession_limit_exceeded", err.Error())
		default:
			writeError(w, http.StatusServiceUnavailable, "capture_deletion_supersession_store_unavailable", "capture deletion supersession could not be persisted")
		}
		return
	}
	if !replayed && (record.Job.State == coordinatedDeletionPending || record.Job.State == coordinatedDeletionRunning) {
		ctx, cancel := durableOperationContext(r)
		defer cancel()
		record.Job, err = s.executeCoordinatedCaptureDeletion(ctx, record)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "capture_deletion_coordination_unavailable", "superseded deletion remains durable and can be resumed")
			return
		}
	}
	s.logger.Info("capture deletion supersession acknowledged", "username", username, "job_id", jobID, "state", record.Job.State, "replayed", replayed)
	writeJSON(w, http.StatusAccepted, record.Job)
}

func (s *Server) cancelCaptureDeletion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	jobID := r.PathValue("jobID")
	var request retryCaptureDeletionRequest
	if !coordinatedCaptureDeletionIDPattern.MatchString(jobID) {
		writeError(w, http.StatusBadRequest, "invalid_capture_deletion_cancel", "The capture deletion job ID is invalid; list jobs with GET /api/v1/capture-deletion-jobs.")
		return
	}
	if err := decodeOptionalJSON(r, &request, 4<<10); err != nil {
		writeDecodeError(w, err, "capture deletion cancellation")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	s.captureDeletionMu.Lock()
	defer s.captureDeletionMu.Unlock()
	record, replayed, err := s.store.cancelCoordinatedCaptureDeletion(jobID, idempotencyKey, username)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "capture_deletion_job_not_found", "capture deletion job was not found")
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, errCaptureDeletionCancelInvalid):
			writeError(w, http.StatusConflict, "capture_deletion_cancel_unsafe", err.Error())
		case errors.Is(err, errCaptureDeletionCancelConflict):
			writeError(w, http.StatusConflict, "capture_deletion_cancel_idempotency_conflict", err.Error())
		default:
			writeError(w, http.StatusServiceUnavailable, "capture_deletion_cancel_store_unavailable", "capture deletion cancellation could not be persisted")
		}
		return
	}
	s.logger.Info("capture deletion cancelled before barrier", "username", username, "job_id", jobID, "replayed", replayed)
	writeJSON(w, http.StatusOK, record.Job)
}

func (s *Server) previewCaptureRetention(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var policy capture.RetentionPolicyInput
	if err := decodeJSON(r, &policy); err != nil || policy.Validate() != nil {
		writeError(w, http.StatusBadRequest, "invalid_capture_retention_policy", "request does not match the bounded capture retention policy schema")
		return
	}
	var hostPreview capture.RetentionPreview
	if err := s.gateway.Call(r.Context(), "PreviewCaptureRetention", gatewayprotocol.PreviewCaptureRetentionParams{Policy: policy}, &hostPreview); err != nil {
		writeError(w, http.StatusConflict, "capture_retention_preview_rejected", err.Error())
		return
	}
	result, err := s.buildCoordinatedCaptureRetentionPreview(r.Context(), hostPreview)
	if err != nil {
		s.logger.Error("capture retention backend preview failed", "username", sessionUsername(r.Context()), "error", err)
		writeError(w, http.StatusServiceUnavailable, "capture_retention_preview_unavailable", "capture retention preview could not enumerate every configured deletion backend")
		return
	}
	if _, err := s.store.recordCoordinatedCaptureRetentionPreview(result, sessionUsername(r.Context())); err != nil {
		if errors.Is(err, errCaptureRetentionPreviewLedgerFull) {
			writeError(w, http.StatusConflict, "capture_retention_preview_limit", "Capture retention preview limit reached: "+err.Error()+".")
			return
		}
		s.logger.Error("capture retention preview persistence failed", "username", sessionUsername(r.Context()), "error", err)
		writeError(w, http.StatusServiceUnavailable, "capture_retention_preview_store_unavailable", "capture retention preview could not be persisted")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) getCaptureRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var result capture.RetentionPolicy
	if err := s.gateway.Call(r.Context(), "GetCaptureRetentionPolicy", gatewayprotocol.EmptyParams{}, &result); err != nil {
		writeError(w, http.StatusServiceUnavailable, "capture_retention_policy_unavailable", "capture retention policy is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type applyCaptureRetentionPolicyRequest struct {
	Password         string                       `json:"password"`
	ExpectedRevision uint64                       `json:"expected_revision"`
	Enabled          bool                         `json:"enabled"`
	Rules            capture.RetentionPolicyInput `json:"rules"`
	RunEverySeconds  int64                        `json:"run_every_seconds"`
	PreviewSHA256    string                       `json:"preview_sha256"`
	PreviewExpiresAt time.Time                    `json:"preview_expires_at"`
}

func (s *Server) applyCaptureRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request applyCaptureRetentionPolicyRequest
	if decodeJSON(r, &request) != nil || request.Rules.Validate() != nil || request.RunEverySeconds < 300 || request.RunEverySeconds > 86400 {
		writeError(w, http.StatusBadRequest, "invalid_capture_retention_policy", "request does not match the capture retention policy schema")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		s.logger.Warn("capture retention policy reauthentication failed", "username", username)
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	params := gatewayprotocol.ApplyCaptureRetentionPolicyParams{Request: capture.ApplyRetentionPolicyRequest{ExpectedRevision: request.ExpectedRevision, Enabled: request.Enabled, Rules: request.Rules, RunEverySeconds: request.RunEverySeconds, PreviewSHA256: request.PreviewSHA256, PreviewExpiresAt: request.PreviewExpiresAt, Administrator: username, IdempotencyKey: idempotencyKey}}
	var result capture.RetentionPolicy
	if err := s.gateway.Call(r.Context(), "ApplyCaptureRetentionPolicy", params, &result); err != nil {
		writeError(w, http.StatusConflict, "capture_retention_policy_rejected", err.Error())
		return
	}
	s.logger.Info("capture retention policy applied", "username", username, "revision", result.Revision, "enabled", result.Enabled)
	writeJSON(w, http.StatusOK, result)
}

type startCaptureRetentionRunRequest struct {
	Password       string                             `json:"password"`
	PolicyRevision uint64                             `json:"policy_revision"`
	Preview        coordinatedCaptureRetentionPreview `json:"preview"`
}

func (s *Server) startCaptureRetentionRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request startCaptureRetentionRunRequest
	if decodeJSONBounded(r, &request, 8<<20) != nil || request.PolicyRevision == 0 || request.Preview.Schema != coordinatedCaptureRetentionPreviewSchema || request.Preview.validate() != nil {
		writeError(w, http.StatusBadRequest, "invalid_capture_retention_run", "request does not match the capture retention run schema")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		s.logger.Warn("capture retention run reauthentication failed", "username", username)
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	recorded, err := s.store.getCoordinatedCaptureRetentionPreview(request.Preview.PreviewSHA256, username)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusConflict, "capture_retention_preview_not_recorded", "manual cleanup requires the exact persisted retention preview returned by this appliance")
		return
	}
	if err != nil {
		s.logger.Error("capture retention preview lookup failed", "username", username, "error", err)
		writeError(w, http.StatusServiceUnavailable, "capture_retention_preview_store_unavailable", "capture retention preview evidence is unavailable")
		return
	}
	if recorded.Preview.PreviewSHA256 != request.Preview.PreviewSHA256 {
		writeError(w, http.StatusConflict, "capture_retention_preview_not_recorded", "manual cleanup requires the exact persisted retention preview returned by this appliance")
		return
	}
	params := gatewayprotocol.StartCaptureRetentionRunParams{Request: capture.StartRetentionRunRequest{PolicyRevision: request.PolicyRevision, PreviewSHA256: request.Preview.HostRetention.PreviewSHA256, PreviewExpiresAt: request.Preview.HostRetention.ExpiresAt, Administrator: username, IdempotencyKey: idempotencyKey, Trigger: capture.RetentionTriggerManual}}
	var result capture.RetentionRun
	if err := s.gateway.Call(r.Context(), "StartCaptureRetentionRun", params, &result); err != nil {
		writeError(w, http.StatusConflict, "capture_retention_run_rejected", err.Error())
		return
	}
	coordinationContext, cancel := durableOperationContext(r)
	defer cancel()
	result, err = s.coordinateCaptureRetentionRun(coordinationContext, result)
	if err != nil {
		s.logger.Error("capture retention coordination failed", "username", username, "run_id", result.ID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "capture_retention_coordination_unavailable", "capture retention run remains durable and will resume automatically")
		return
	}
	s.logger.Info("capture retention run completed", "username", username, "run_id", result.ID, "state", result.State, "deleted", result.DeletedSessions, "failed", result.FailedSessions)
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) listCaptureRetentionRuns(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var result []capture.RetentionRun
	if err := s.gateway.Call(r.Context(), "ListCaptureRetentionRuns", gatewayprotocol.EmptyParams{}, &result); err != nil {
		writeError(w, http.StatusServiceUnavailable, "capture_retention_runs_unavailable", "capture retention runs are unavailable")
		return
	}
	if result == nil {
		result = []capture.RetentionRun{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": result})
}

func (s *Server) captureRetentionSchedulerStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var result capture.RetentionSchedulerStatus
	if err := s.gateway.Call(r.Context(), "GetCaptureRetentionSchedulerStatus", gatewayprotocol.EmptyParams{}, &result); err != nil {
		writeError(w, http.StatusServiceUnavailable, "capture_retention_scheduler_unavailable", "capture retention scheduler status is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type captureExportRequest struct {
	Password string `json:"password"`
}

func (s *Server) captureExportHistory(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")
	if !capture.ValidSessionID(sessionID) {
		writeError(w, http.StatusBadRequest, "invalid_capture_id", "capture session ID is invalid")
		return
	}
	records, err := s.store.ListCaptureExports(sessionID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "export_history_unavailable", "capture export history is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exports": records})
}

func (s *Server) exportCaptureFile(w http.ResponseWriter, r *http.Request) {
	sessionID, fileName := r.PathValue("sessionID"), r.PathValue("fileName")
	if !capture.ValidSessionID(sessionID) || !validCaptureArtifactName(fileName) {
		writeError(w, http.StatusBadRequest, "invalid_capture_artifact", "capture session or file name is invalid")
		return
	}
	var request captureExportRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "capture export")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		s.logger.Warn("capture export reauthentication failed", "username", username, "capture_id", sessionID, "file_name", fileName)
		return
	}
	var view capture.View
	if err := s.gateway.Call(r.Context(), "GetCaptureStats", gatewayprotocol.GetCaptureStatsParams{SessionID: sessionID}, &view); err != nil || view.Active || view.Manifest == nil || view.Session.ID != sessionID || view.Manifest.SessionID != sessionID {
		writeError(w, http.StatusConflict, "capture_not_finalized", "capture must be finalized before export")
		return
	}
	var artifact *capture.CaptureFile
	matches := 0
	for index := range view.Manifest.Files {
		if view.Manifest.Files[index].Name == fileName {
			if artifact == nil {
				artifact = &view.Manifest.Files[index]
			}
			matches++
		}
	}
	if artifact == nil {
		writeError(w, http.StatusNotFound, "capture_artifact_not_found", "capture artifact is not present in the final manifest")
		return
	}
	if matches != 1 || artifact.SizeBytes <= 0 || !validSHA256(artifact.SHA256) {
		writeError(w, http.StatusConflict, "capture_manifest_invalid", "capture artifact manifest is invalid")
		return
	}
	start, end, partial, err := parseByteRange(r.Header.Get("Range"), artifact.SizeBytes)
	if err != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", artifact.SizeBytes))
		writeError(w, http.StatusRequestedRangeNotSatisfiable, "invalid_range", err.Error())
		return
	}
	record, err := s.store.BeginCaptureExport(CaptureExportRecord{SessionID: sessionID, FileName: fileName, SHA256: artifact.SHA256, Username: username, RangeStart: start, RangeEnd: end})
	if err != nil {
		s.logger.Error("capture export history start failed", "error", err, "capture_id", sessionID, "file_name", fileName)
		switch {
		case errors.Is(err, errCaptureExportLedgerFull):
			writeError(w, http.StatusInsufficientStorage, "capture_export_history_full", "Capture export history is full: "+err.Error()+".")
		case errors.Is(err, syscall.ENOSPC):
			writeError(w, http.StatusInsufficientStorage, "insufficient_storage", "The appliance disk is full, so the export audit record cannot be written; free space and try again.")
		default:
			writeError(w, http.StatusServiceUnavailable, "export_audit_unavailable", "The export cannot start because its audit record could not be written; try again.")
		}
		return
	}
	defer func() {
		stored, recordErr := s.store.FinishCaptureExport(record.ID, record.BytesSent, record.Complete)
		if recordErr != nil {
			s.logger.Error("capture export history write failed", "error", recordErr, "capture_id", sessionID, "file_name", fileName)
			return
		}
		s.logger.Info("capture artifact export", "username", username, "capture_id", sessionID, "file_name", fileName, "sha256", artifact.SHA256, "range_start", start, "range_end", end, "bytes_sent", record.BytesSent, "complete", record.Complete, "export_id", stored.ID)
	}()

	length := int64(0)
	if artifact.SizeBytes > 0 {
		length = end - start + 1
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": fileName}))
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("ETag", `"`+artifact.SHA256+`"`)
	w.Header().Set("X-ShakerProxy-SHA256", artifact.SHA256)
	if digest, decodeErr := hex.DecodeString(artifact.SHA256); decodeErr == nil {
		w.Header().Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(digest))
	}
	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, artifact.SizeBytes))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	if length == 0 {
		record.Complete = true
		return
	}

	controller := http.NewResponseController(w)
	for offset := start; offset <= end; {
		requested := min(int64(capture.MaxArtifactChunkBytes), end-offset+1)
		var chunk capture.ArtifactChunk
		params := gatewayprotocol.ReadCaptureArtifactParams{SessionID: sessionID, FileName: fileName, Offset: offset, Length: int(requested)}
		if err := s.gateway.Call(r.Context(), "ReadCaptureArtifact", params, &chunk); err != nil {
			s.logger.Error("capture export read failed", "error", err, "capture_id", sessionID, "file_name", fileName, "offset", offset)
			return
		}
		if chunk.SessionID != sessionID || chunk.FileName != fileName || chunk.FileSHA256 != artifact.SHA256 || chunk.TotalBytes != artifact.SizeBytes || chunk.Offset != offset || int64(len(chunk.Data)) != requested {
			s.logger.Error("capture export integrity mismatch", "capture_id", sessionID, "file_name", fileName, "offset", offset)
			return
		}
		_ = controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
		written, writeErr := w.Write(chunk.Data)
		record.BytesSent += int64(written)
		if writeErr != nil || written != len(chunk.Data) {
			return
		}
		offset += int64(written)
	}
	record.Complete = record.BytesSent == length
}

func validCaptureArtifactName(name string) bool {
	return name != "" && len(name) <= 255 && !strings.ContainsAny(name, "/\\\x00\r\n") && (strings.HasSuffix(name, ".pcap") || strings.HasSuffix(name, ".pcapng"))
}

func parseByteRange(header string, size int64) (start, end int64, partial bool, err error) {
	if size < 0 {
		return 0, 0, false, errors.New("capture artifact size is invalid")
	}
	if header == "" {
		if size == 0 {
			return 0, 0, false, nil
		}
		return 0, size - 1, false, nil
	}
	if size == 0 || !strings.HasPrefix(header, "bytes=") || strings.Contains(header, ",") {
		return 0, 0, false, errors.New("only one explicit byte range is supported")
	}
	parts := strings.Split(strings.TrimPrefix(header, "bytes="), "-")
	if len(parts) != 2 || parts[0] == "" {
		return 0, 0, false, errors.New("only start-end or start- byte ranges are supported")
	}
	if !decimalDigits(parts[0]) || (parts[1] != "" && !decimalDigits(parts[1])) {
		return 0, 0, false, errors.New("byte range contains invalid digits")
	}
	start, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, false, errors.New("byte range start is outside the artifact")
	}
	end = size - 1
	if parts[1] != "" {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil || end < start {
			return 0, 0, false, errors.New("byte range end is invalid")
		}
		if end >= size {
			end = size - 1
		}
	}
	return start, end, true, nil
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	query, err := parseDeviceListQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	snapshot, err := s.inventory.Snapshot()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is unavailable")
		return
	}
	snapshot.Devices = filterAndSortDevices(snapshot.Devices, query, snapshot.GeneratedAt)
	response := deviceListResponse{Snapshot: snapshot}
	if mayReadTraffic(r) {
		response.PlatformHints = platformHintsFor(snapshot.Devices, s.devicePlatformHints(r.Context()))
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) exportDeviceAliases(w http.ResponseWriter, r *http.Request) {
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	exported, err := s.inventory.ExportAliasesTags()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device alias export is unavailable")
		return
	}
	format := r.URL.Query().Get("format")
	var body []byte
	switch format {
	case "json":
		body, err = json.MarshalIndent(exported, "", "  ")
		if err == nil {
			body = append(body, '\n')
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="shakerproxy-device-aliases.json"`)
	case "csv":
		var buffer bytes.Buffer
		writer := csv.NewWriter(&buffer)
		err = writer.Write([]string{"device_id", "friendly_name", "alias_revision", "tags_json"})
		for _, entry := range exported.Entries {
			if err != nil {
				break
			}
			tags, encodeErr := json.Marshal(entry.Tags)
			if encodeErr != nil {
				err = encodeErr
				break
			}
			err = writer.Write([]string{entry.DeviceID, entry.FriendlyName, strconv.FormatUint(entry.AliasRevision, 10), string(tags)})
		}
		writer.Flush()
		if err == nil {
			err = writer.Error()
		}
		body = buffer.Bytes()
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="shakerproxy-device-aliases.csv"`)
	default:
		writeError(w, http.StatusBadRequest, "invalid_format", "format must be json or csv")
		return
	}
	if err != nil || len(body) > deviceinventory.MaxAliasTagExportBytes {
		writeError(w, http.StatusServiceUnavailable, "export_unavailable", "device alias export exceeds its bounded output limit")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

type deviceAliasImportPreviewRequest struct {
	Format  string `json:"format"`
	Content string `json:"content"`
	Reason  string `json:"reason"`
}

func (s *Server) previewDeviceAliasImport(w http.ResponseWriter, r *http.Request) {
	var request deviceAliasImportPreviewRequest
	if decodeJSONBounded(r, &request, 2*deviceinventory.MaxAliasTagImportBytes+(128<<10)) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request does not match the bounded device alias/tag import schema")
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	entries, err := deviceinventory.ParseAliasTagImport(request.Format, []byte(request.Content))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_import", err.Error())
		return
	}
	preview, err := s.inventory.PreviewAliasTagImport(entries, request.Reason)
	if err != nil {
		s.writeDeviceMutationError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, preview)
}

type deviceAliasImportApplyRequest struct {
	Password string                                `json:"password"`
	Preview  deviceinventory.AliasTagImportPreview `json:"preview"`
}

func (s *Server) applyDeviceAliasImport(w http.ResponseWriter, r *http.Request) {
	operationID, ok := requestOperationID(r, deviceinventory.ValidOperationID)
	if !ok {
		writeInvalidIdempotencyKey(w)
		return
	}
	var request deviceAliasImportApplyRequest
	if err := decodeJSONBounded(r, &request, 4*deviceinventory.MaxAliasTagImportBytes); err != nil {
		writeDecodeError(w, err, "device alias/tag import apply")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	result, err := s.inventory.ApplyAliasTagImport(sessionUsername(r.Context()), operationID, request.Preview)
	if err != nil {
		s.writeDeviceMutationError(w, err)
		return
	}
	s.invalidateDeviceNames()
	s.logger.Info("device aliases and tags imported", "username", sessionUsername(r.Context()), "updated_devices", result.UpdatedDevices, "audit_id", result.Audit.ID, "replayed", result.Replayed)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceID")
	if !deviceinventory.ValidDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid_device_id", "device ID is invalid")
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	device, err := s.inventory.Get(deviceID)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "device_not_found", "device was not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, device)
}

type addressAliasRequest struct {
	Password         string     `json:"password"`
	Name             string     `json:"name"`
	Prefix           string     `json:"prefix"`
	Interface        string     `json:"interface"`
	VLANID           *int       `json:"vlan_id,omitempty"`
	ValidFrom        time.Time  `json:"valid_from"`
	ValidUntil       *time.Time `json:"valid_until,omitempty"`
	Priority         int        `json:"priority"`
	Confidence       int        `json:"confidence"`
	Reason           string     `json:"reason"`
	ExpectedRevision *uint64    `json:"expected_revision,omitempty"`
}

func (request addressAliasRequest) input() deviceinventory.AddressAliasInput {
	return deviceinventory.AddressAliasInput{Name: request.Name, Prefix: request.Prefix, Interface: request.Interface, VLANID: request.VLANID, ValidFrom: request.ValidFrom, ValidUntil: request.ValidUntil, Priority: request.Priority, Confidence: request.Confidence, Reason: request.Reason}
}

func (s *Server) createAddressAlias(w http.ResponseWriter, r *http.Request) {
	operationID, ok := requestOperationID(r, deviceinventory.ValidOperationID)
	if !ok {
		writeInvalidIdempotencyKey(w)
		return
	}
	var request addressAliasRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "address alias creation")
		return
	}
	if request.ExpectedRevision != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "expected_revision is only used when updating an address alias; remove it to create one.")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	result, err := s.inventory.CreateAddressAlias(sessionUsername(r.Context()), operationID, request.input())
	if err != nil {
		s.writeDeviceMutationError(w, err)
		return
	}
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	s.logger.Info("address alias created", "username", sessionUsername(r.Context()), "address_alias_id", result.Alias.ID, "audit_id", result.Audit.ID, "replayed", result.Replayed)
	writeJSON(w, status, result)
}

func (s *Server) updateAddressAlias(w http.ResponseWriter, r *http.Request) {
	aliasID := r.PathValue("aliasID")
	if !deviceinventory.ValidAddressAliasID(aliasID) {
		writeError(w, http.StatusBadRequest, "invalid_address_alias_id", "The address alias ID is invalid; list aliases with GET /api/v1/address-aliases.")
		return
	}
	operationID, ok := requestOperationID(r, deviceinventory.ValidOperationID)
	if !ok {
		writeInvalidIdempotencyKey(w)
		return
	}
	var request addressAliasRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "address alias update")
		return
	}
	if request.ExpectedRevision == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Include expected_revision (the alias revision you edited) so concurrent changes are not overwritten.")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	result, err := s.inventory.UpdateAddressAlias(aliasID, sessionUsername(r.Context()), operationID, deviceinventory.AddressAliasUpdate{AddressAliasInput: request.input(), ExpectedRevision: *request.ExpectedRevision})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "address_alias_not_found", "address alias was not found")
			return
		}
		s.writeDeviceMutationError(w, err)
		return
	}
	s.logger.Info("address alias updated", "username", sessionUsername(r.Context()), "address_alias_id", aliasID, "audit_id", result.Audit.ID, "revision", result.Alias.Revision, "replayed", result.Replayed)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) resolveAddressAlias(w http.ResponseWriter, r *http.Request) {
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	address, addressErr := netip.ParseAddr(r.URL.Query().Get("address"))
	// "at" defaults to now: the common question is "what is this address now?"
	occurredAt, timeErr := s.now(), error(nil)
	if value := r.URL.Query().Get("at"); value != "" {
		occurredAt, timeErr = time.Parse(time.RFC3339Nano, value)
	}
	var vlanID *int
	if value := r.URL.Query().Get("vlan_id"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "vlan_id must be an integer between 1 and 4094.")
			return
		}
		vlanID = &parsed
	}
	if addressErr != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "address must be an IPv4 or IPv6 address, for example ?address=10.77.0.23&interface=lab0.")
		return
	}
	if timeErr != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "at must be an RFC 3339 timestamp such as 2026-09-29T10:00:00Z (omit it to resolve for now).")
		return
	}
	result, err := s.inventory.ResolveAddressAlias(address, r.URL.Query().Get("interface"), vlanID, occurredAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type updateDeviceMetadataRequest struct {
	Password     string    `json:"password"`
	FriendlyName *string   `json:"friendly_name,omitempty"`
	Owner        *string   `json:"owner,omitempty"`
	Location     *string   `json:"location,omitempty"`
	Category     *string   `json:"category,omitempty"`
	Icon         *string   `json:"icon,omitempty"`
	Tags         *[]string `json:"tags,omitempty"`
	Notes        *string   `json:"notes,omitempty"`
}

func (s *Server) updateDeviceMetadata(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceID")
	if !deviceinventory.ValidDeviceID(deviceID) {
		writeInvalidDeviceID(w)
		return
	}
	operationID, ok := requestOperationID(r, deviceinventory.ValidOperationID)
	if !ok {
		writeInvalidIdempotencyKey(w)
		return
	}
	var request updateDeviceMetadataRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "device metadata")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	result, err := s.inventory.PatchMetadata(deviceID, sessionUsername(r.Context()), operationID, deviceinventory.DeviceMetadataPatch{FriendlyName: request.FriendlyName, Owner: request.Owner, Location: request.Location, Category: request.Category, Icon: request.Icon, Tags: request.Tags, Notes: request.Notes})
	if err != nil {
		s.writeDeviceMutationError(w, err)
		return
	}
	s.invalidateDeviceNames()
	s.logger.Info("device metadata updated", "username", sessionUsername(r.Context()), "device_id", deviceID, "audit_id", result.Audit.ID, "replayed", result.Replayed)
	writeJSON(w, http.StatusOK, result)
}

type nameDeviceAddressRequest struct {
	Password string `json:"password"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	DeviceID string `json:"device_id"`
}

// nameDeviceAddress names the device at an IP address, the way a router's
// client alias does: it creates the device if it was not seen yet, and every
// MAC that appears at the address joins it.
func (s *Server) nameDeviceAddress(w http.ResponseWriter, r *http.Request) {
	operationID, ok := requestOperationID(r, deviceinventory.ValidOperationID)
	if !ok {
		writeInvalidIdempotencyKey(w)
		return
	}
	var request nameDeviceAddressRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "device name")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	result, err := s.inventory.NameAddress(sessionUsername(r.Context()), operationID, deviceinventory.AddressName{Name: request.Name, Address: request.Address, DeviceID: request.DeviceID})
	if errors.Is(err, deviceinventory.ErrAddressAlreadyNamed) {
		writeError(w, http.StatusConflict, "address_already_named", strings.TrimPrefix(err.Error(), deviceinventory.ErrAddressAlreadyNamed.Error()+": "))
		return
	}
	if err != nil {
		s.writeDeviceMutationError(w, err)
		return
	}
	s.invalidateDeviceNames()
	deviceID := ""
	if len(result.Devices) > 0 {
		deviceID = result.Devices[0].ID
	}
	s.logger.Info("device named by address", "username", sessionUsername(r.Context()), "device_id", deviceID, "audit_id", result.Audit.ID, "replayed", result.Replayed)
	writeJSON(w, http.StatusOK, result)
}

type unpinDeviceAddressRequest struct {
	Password string `json:"password"`
}

func (s *Server) unpinDeviceAddress(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceID")
	if !deviceinventory.ValidDeviceID(deviceID) {
		writeInvalidDeviceID(w)
		return
	}
	operationID, ok := requestOperationID(r, deviceinventory.ValidOperationID)
	if !ok {
		writeInvalidIdempotencyKey(w)
		return
	}
	var request unpinDeviceAddressRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "device address")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	result, err := s.inventory.UnpinAddress(deviceID, sessionUsername(r.Context()), operationID)
	if err != nil {
		s.writeDeviceMutationError(w, err)
		return
	}
	s.invalidateDeviceNames()
	s.logger.Info("device address unpinned", "username", sessionUsername(r.Context()), "device_id", deviceID, "audit_id", result.Audit.ID, "replayed", result.Replayed)
	writeJSON(w, http.StatusOK, result)
}

type updateDeviceAliasRequest struct {
	Password         string `json:"password"`
	FriendlyName     string `json:"friendly_name"`
	Reason           string `json:"reason"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

func (s *Server) updateDeviceAlias(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceID")
	if !deviceinventory.ValidDeviceID(deviceID) {
		writeInvalidDeviceID(w)
		return
	}
	operationID, ok := requestOperationID(r, deviceinventory.ValidOperationID)
	if !ok {
		writeInvalidIdempotencyKey(w)
		return
	}
	var request updateDeviceAliasRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "device alias")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	result, err := s.inventory.UpdateAlias(deviceID, sessionUsername(r.Context()), operationID, deviceinventory.AliasUpdate{FriendlyName: request.FriendlyName, Reason: request.Reason, ExpectedRevision: request.ExpectedRevision})
	if err != nil {
		s.writeDeviceMutationError(w, err)
		return
	}
	s.invalidateDeviceNames()
	// A replayed mutation may reference a device that was later merged away,
	// so the result can legitimately contain no devices.
	aliasRevision := uint64(0)
	if len(result.Devices) > 0 {
		aliasRevision = result.Devices[0].AliasRevision
	}
	s.logger.Info("device alias updated", "username", sessionUsername(r.Context()), "device_id", deviceID, "audit_id", result.Audit.ID, "alias_revision", aliasRevision, "replayed", result.Replayed)
	writeJSON(w, http.StatusOK, result)
}

type mergeDeviceRequest struct {
	Password       string `json:"password"`
	SourceDeviceID string `json:"source_device_id"`
}

func (s *Server) mergeDevice(w http.ResponseWriter, r *http.Request) {
	targetDeviceID := r.PathValue("deviceID")
	if !deviceinventory.ValidDeviceID(targetDeviceID) {
		writeInvalidDeviceID(w)
		return
	}
	operationID, ok := requestOperationID(r, deviceinventory.ValidOperationID)
	if !ok {
		writeInvalidIdempotencyKey(w)
		return
	}
	var request mergeDeviceRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "device merge")
		return
	}
	if !deviceinventory.ValidDeviceID(request.SourceDeviceID) {
		writeError(w, http.StatusBadRequest, "invalid_request", "source_device_id must be a device ID (device-<32 hex>); find it with GET /api/v1/devices.")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	result, err := s.inventory.MergeDevices(targetDeviceID, request.SourceDeviceID, sessionUsername(r.Context()), operationID)
	if err != nil {
		s.writeDeviceMutationError(w, err)
		return
	}
	s.invalidateDeviceNames()
	s.logger.Info("devices merged", "username", sessionUsername(r.Context()), "target_device_id", targetDeviceID, "source_device_id", request.SourceDeviceID, "audit_id", result.Audit.ID, "replayed", result.Replayed)
	writeJSON(w, http.StatusOK, result)
}

type splitDeviceRequest struct {
	Password  string                         `json:"password"`
	Selection deviceinventory.SplitSelection `json:"selection"`
}

func (s *Server) splitDevice(w http.ResponseWriter, r *http.Request) {
	sourceDeviceID := r.PathValue("deviceID")
	if !deviceinventory.ValidDeviceID(sourceDeviceID) {
		writeInvalidDeviceID(w)
		return
	}
	operationID, ok := requestOperationID(r, deviceinventory.ValidOperationID)
	if !ok {
		writeInvalidIdempotencyKey(w)
		return
	}
	var request splitDeviceRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "device split")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	result, err := s.inventory.SplitDevice(sourceDeviceID, sessionUsername(r.Context()), operationID, request.Selection)
	if err != nil {
		s.writeDeviceMutationError(w, err)
		return
	}
	s.invalidateDeviceNames()
	s.logger.Info("device split", "username", sessionUsername(r.Context()), "source_device_id", sourceDeviceID, "result_device_ids", result.Audit.ResultDeviceIDs, "audit_id", result.Audit.ID, "replayed", result.Replayed)
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, result)
}

func (s *Server) writeDeviceMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		writeError(w, http.StatusNotFound, "device_not_found", "device was not found")
	case errors.Is(err, deviceinventory.ErrOperationConflict):
		writeError(w, http.StatusConflict, "idempotency_conflict", "Idempotency-Key was already used for a different device mutation")
	case errors.Is(err, deviceinventory.ErrAliasRevisionConflict):
		writeError(w, http.StatusConflict, "alias_revision_conflict", "device alias changed since it was loaded")
	case errors.Is(err, deviceinventory.ErrAddressAliasRevisionConflict):
		writeError(w, http.StatusConflict, "address_alias_revision_conflict", "address alias changed since it was loaded")
	case errors.Is(err, deviceinventory.ErrAliasTagImportStale):
		writeError(w, http.StatusConflict, "alias_tag_import_stale", "device aliases or tags changed after the reviewed import preview")
	case errors.Is(err, deviceinventory.ErrCapacity):
		writeError(w, http.StatusInsufficientStorage, "inventory_capacity_reached", strings.TrimPrefix(err.Error(), deviceinventory.ErrMutationRejected.Error()+": ")+"; remove unused entries and try again.")
	case errors.Is(err, deviceinventory.ErrMutationRejected):
		writeError(w, http.StatusConflict, "device_mutation_rejected", err.Error())
	case errors.Is(err, syscall.ENOSPC):
		writeError(w, http.StatusInsufficientStorage, "insufficient_storage", "The appliance disk is full; free space and try again.")
	default:
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "The device inventory could not be saved; check appliance storage and try again.")
	}
}

func (s *Server) refreshInventory() (deviceinventory.Snapshot, error) {
	if s.inventory == nil {
		return deviceinventory.Snapshot{}, errors.New("device inventory is not configured")
	}
	if s.keaLeasePath == "" {
		return s.inventory.Snapshot()
	}
	leases, err := readKeaDHCP4Leases(s.keaLeasePath)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		// Without ShakerProxy DHCP (a single-arm lab, or before the DHCP
		// service first runs) the lease file is missing or still owned by
		// Kea's own package. Devices are then found from the gateway's
		// neighbor tables alone, so an unreadable file must not hide them.
		// Malformed lease contents remain an error.
		if errors.Is(err, fs.ErrPermission) {
			s.noteLeaseReadProblem(err)
		}
		return s.withObservedDHCP(s.withNeighborEvidence(s.inventory.Snapshot()))
	}
	if err != nil {
		return deviceinventory.Snapshot{}, err
	}
	s.noteLeaseReadProblem(nil)
	s.scopeDHCP4Leases(leases)
	return s.withObservedDHCP(s.withNeighborEvidence(s.inventory.ReconcileDHCP4(leases)))
}

// readKeaDHCP4Leases is replaced in tests.
var readKeaDHCP4Leases = deviceinventory.ReadKeaDHCP4Leases

// noteLeaseReadProblem logs a lease-file problem once, and its recovery.
func (s *Server) noteLeaseReadProblem(err error) {
	s.leaseReadProblem.Lock()
	defer s.leaseReadProblem.Unlock()
	switch {
	case err == nil && s.lastLeaseReadProblem != "":
		s.logger.Info("DHCP lease file is readable again")
		s.lastLeaseReadProblem = ""
	case err != nil && err.Error() != s.lastLeaseReadProblem:
		s.logger.Warn("DHCP lease file is unreadable; devices are discovered from the gateway's neighbor tables only", "error", err)
		s.lastLeaseReadProblem = err.Error()
	}
}

func (s *Server) scopeDHCP4Leases(leases []deviceinventory.DHCP4Lease) {
	if len(leases) == 0 || s.gateway.SocketPath == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var status gatewayprotocol.Status
	if err := s.gateway.CallWithTimeout(ctx, "GetManagedState", gatewayprotocol.EmptyParams{}, &status, time.Second); err != nil || status.LabInterface == "" || status.LabScopePlanHash == "" {
		return
	}
	for index := range leases {
		leases[index].Interface = status.LabInterface
		if status.LabVLANID != nil {
			vlanID := *status.LabVLANID
			leases[index].VLANID = &vlanID
		}
		leases[index].ScopePlanSHA256 = status.LabScopePlanHash
	}
}

func (s *Server) RunInventorySync(ctx context.Context, interval time.Duration) {
	if s.inventory == nil || s.keaLeasePath == "" {
		return
	}
	if interval < time.Second {
		interval = 5 * time.Second
	}
	lastFailure := ""
	refresh := func() {
		_, err := s.refreshInventory()
		if err == nil {
			if lastFailure != "" {
				s.logger.Info("device inventory evidence recovered")
			}
			lastFailure = ""
			return
		}
		if err.Error() != lastFailure {
			s.logger.Warn("device inventory refresh failed", "error", err)
			lastFailure = err.Error()
		}
	}
	refresh()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
			return
		}
		session, ok := s.authenticateSession(token)
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid_session", "The session is invalid or has expired; sign in again with POST /api/v1/auth/login.")
			return
		}
		setSessionExpiryHeader(w, session)
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), token, session)))
	})
}

func (s *Server) requireAuthOrScope(required apitoken.Scope, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
			return
		}
		if session, ok := s.authenticateSession(secret); ok {
			setSessionExpiryHeader(w, session)
			next.ServeHTTP(w, r.WithContext(withSession(r.Context(), secret, session)))
			return
		}
		if s.apiTokens == nil {
			writeError(w, http.StatusUnauthorized, "invalid_api_token", "API token authentication is unavailable")
			return
		}
		if !s.allowTokenRequest(secret, time.Now().UTC()) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "token_rate_limited", "API token request rate limit exceeded")
			return
		}
		principal, err := s.apiTokens.Authenticate(secret, required, r.Method, r.URL.Path, tokenRequestResourceID(r))
		if errors.Is(err, apitoken.ErrResourceForbidden) {
			writeError(w, http.StatusForbidden, "resource_restricted", "API token is not authorized for this resource")
			return
		}
		if errors.Is(err, apitoken.ErrForbidden) {
			writeError(w, http.StatusForbidden, "insufficient_scope", "API token does not grant the required scope")
			return
		}
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_api_token", "API token is invalid, expired, or revoked")
			return
		}
		ctx := context.WithValue(r.Context(), sessionContextKey{}, principal.Actor)
		ctx = context.WithValue(ctx, apiPrincipalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requireAPITokenScope(required apitoken.Scope, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication_required", "API token authentication required")
			return
		}
		if _, session := s.authenticateSession(secret); session {
			writeError(w, http.StatusForbidden, "api_token_required", "this endpoint requires a scoped API token")
			return
		}
		if s.apiTokens == nil {
			writeError(w, http.StatusUnauthorized, "invalid_api_token", "API token authentication is unavailable")
			return
		}
		if !s.allowTokenRequest(secret, time.Now().UTC()) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "token_rate_limited", "API token request rate limit exceeded")
			return
		}
		principal, err := s.apiTokens.Authenticate(secret, required, r.Method, r.URL.Path, "")
		if errors.Is(err, apitoken.ErrForbidden) {
			writeError(w, http.StatusForbidden, "insufficient_scope", "API token does not grant the required scope")
			return
		}
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_api_token", "API token is invalid, expired, or revoked")
			return
		}
		ctx := context.WithValue(r.Context(), sessionContextKey{}, principal.Actor)
		ctx = context.WithValue(ctx, apiPrincipalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") || strings.Contains(header, ",") {
		return "", false
	}
	value := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	return value, value != "" && !strings.ContainsAny(value, " \t\r\n")
}

func (s *Server) allowTokenRequest(secret string, now time.Time) bool {
	digest := sha256.Sum256([]byte(secret))
	key := hex.EncodeToString(digest[:12])
	s.tokenRateMu.Lock()
	defer s.tokenRateMu.Unlock()
	if s.tokenGlobalRate.StartedAt.IsZero() || now.Sub(s.tokenGlobalRate.StartedAt) >= time.Minute {
		s.tokenGlobalRate = tokenRateWindow{StartedAt: now}
	}
	s.tokenGlobalRate.Requests++
	if s.tokenGlobalRate.Requests > 2400 {
		return false
	}
	window := s.tokenRates[key]
	if window.StartedAt.IsZero() || now.Sub(window.StartedAt) >= time.Minute {
		window = tokenRateWindow{StartedAt: now}
	}
	window.Requests++
	if len(s.tokenRates) > 4096 {
		s.tokenRates = make(map[string]tokenRateWindow)
	}
	s.tokenRates[key] = window
	return window.Requests <= 120
}

func tokenRequestResourceID(r *http.Request) string {
	if id := r.PathValue("deviceID"); id != "" {
		return id
	}
	return r.PathValue("caseID")
}

func sessionUsername(ctx context.Context) string {
	username, _ := ctx.Value(sessionContextKey{}).(string)
	return username
}

func (s *Server) validateHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if _, ok := s.allowedHosts[host]; !ok {
			writeError(w, http.StatusBadRequest, "invalid_host", "host header is not allowed")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			valid := false
			for allowed := range s.allowedHosts {
				if subtle.ConstantTimeCompare([]byte(origin), []byte("http://"+allowed)) == 1 || subtle.ConstantTimeCompare([]byte(origin), []byte("https://"+allowed)) == 1 {
					valid = true
				}
			}
			if !valid {
				writeError(w, http.StatusForbidden, "invalid_origin", "origin is not allowed")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(r *http.Request, dst any) error {
	return decodeJSONBounded(r, dst, 32<<10)
}

func decodeJSONBounded(r *http.Request, dst any, maxBytes int64) error {
	if err := checkJSONContentType(r); err != nil {
		return err
	}
	body, err := readBoundedBody(r, maxBytes)
	if err != nil {
		return err
	}
	return decodeStrictJSONBytes(body, dst)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func Shutdown(ctx context.Context, server *http.Server) error { return server.Shutdown(ctx) }
