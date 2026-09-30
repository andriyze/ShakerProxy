package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	urlpkg "net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	ingestserver "shakerproxy.dev/shakerproxy/apps/ingestd/internal/server"
	"shakerproxy.dev/shakerproxy/internal/cloudconnector"
	"shakerproxy.dev/shakerproxy/internal/detection"
	"shakerproxy.dev/shakerproxy/internal/forwarder"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/savedview"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "-healthcheck" {
		client := http.Client{Timeout: 2 * time.Second}
		response, err := client.Get("http://127.0.0.1:8081/healthz")
		if err != nil || response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		response.Body.Close()
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	token, err := ingestserver.LoadToken(envOr("SHAKERPROXY_INGEST_TOKEN_FILE", "/run/secrets/ingest_token"))
	if err != nil {
		logger.Error("ingest token unavailable", "error", err)
		os.Exit(1)
	}
	queryToken, err := ingestserver.LoadToken(envOr("SHAKERPROXY_EVENT_QUERY_TOKEN_FILE", "/run/secrets/event_query_token"))
	if err != nil {
		logger.Error("event query token unavailable", "error", err)
		os.Exit(1)
	}
	maxBytes, err := strconv.ParseInt(envOr("SHAKERPROXY_INGEST_MAX_BYTES", "1073741824"), 10, 64)
	if err != nil || maxBytes < 1<<20 || maxBytes > 64<<30 {
		logger.Error("invalid ingestion spool limit")
		os.Exit(1)
	}
	spool := &ingest.Spool{Root: envOr("SHAKERPROXY_INGEST_SPOOL", "/var/lib/shakerproxy/spool"), MaxBytes: maxBytes, ReserveBytes: ingest.DefaultReserve}
	var database *sql.DB
	var databaseProbe func(context.Context) error
	var databaseSink ingest.PostgresSink
	var savedViews *savedview.PostgresStore
	var savedViewToken []byte
	var deletionToken []byte
	var captureDeletions ingestserver.CaptureEventDeletionLifecycle
	var selectionDeletions ingestserver.EventSelectionDeletionLifecycle
	databaseURLFile := os.Getenv("SHAKERPROXY_DATABASE_URL_FILE")
	if databaseURLFile != "" {
		databaseURL, loadErr := loadDatabaseURL(databaseURLFile)
		if loadErr != nil {
			logger.Error("database secret unavailable", "error", loadErr)
			os.Exit(1)
		}
		database, err = sql.Open("pgx", databaseURL)
		if err != nil {
			logger.Error("database configuration rejected", "error", err)
			os.Exit(1)
		}
		database.SetMaxOpenConns(4)
		database.SetMaxIdleConns(2)
		database.SetConnMaxLifetime(30 * time.Minute)
		databaseSink = ingest.PostgresSink{DB: database, Attributor: &inventory.Attributor{Store: &inventory.Store{Path: envOr("SHAKERPROXY_INVENTORY_PATH", "/var/lib/shakerproxy/inventory/inventory.json")}}}
		savedViewToken, err = ingestserver.LoadToken(envOr("SHAKERPROXY_SAVED_VIEW_TOKEN_FILE", "/run/secrets/saved_view_token"))
		if err != nil {
			logger.Error("saved view storage token unavailable", "error", err)
			os.Exit(1)
		}
		savedViews = &savedview.PostgresStore{DB: database}
		deletionToken, err = ingestserver.LoadToken(envOr("SHAKERPROXY_EVENT_DELETION_TOKEN_FILE", "/run/secrets/event_deletion_token"))
		if err != nil {
			logger.Error("capture event deletion token unavailable", "error", err)
			os.Exit(1)
		}
		captureDeletions = ingest.CaptureEventDeletionService{Spool: spool, Database: databaseSink}
		selectionDeletions = ingest.EventSelectionDeletionService{Spool: spool, Database: databaseSink}
		databaseProbe = databaseSink.Ping
		logger.Info("PostgreSQL normalized event sink configured")
	} else {
		logger.Warn("PostgreSQL drain disabled; events will remain in the bounded spool")
	}
	forwarders := &forwarder.Manager{Root: envOr("SHAKERPROXY_FORWARDER_ROOT", "/var/lib/shakerproxy/forwarders")}
	detections, err := detection.New(envOr("SHAKERPROXY_DETECTION_STATE", "/var/lib/shakerproxy/spool/detections.json"), detection.Config{AuthorizedDHCPServers: detection.SortedSet(os.Getenv("SHAKERPROXY_AUTHORIZED_DHCP_SERVERS")), AuthorizedRAs: detection.SortedSet(os.Getenv("SHAKERPROXY_AUTHORIZED_ROUTER_ADVERTISEMENTS")), GatewayBindings: detection.GatewayBindingSet(os.Getenv("SHAKERPROXY_GATEWAY_BINDINGS"))})
	if err != nil {
		logger.Error("native detection state unavailable", "error", err)
		os.Exit(1)
	}
	var cloudMetadata *cloudconnector.LocalMetadataClient
	if socket := strings.TrimSpace(os.Getenv("SHAKERPROXY_CLOUD_CONNECTOR_SOCKET")); socket != "" {
		cloudMetadata, err = cloudconnector.NewLocalMetadataClient(socket, 10*time.Second)
		if err != nil {
			logger.Error("cloud metadata connector rejected", "error", err)
			os.Exit(1)
		}
	}
	serverConfig := ingestserver.Config{Spool: spool, Token: token, QueryToken: queryToken, SavedViewToken: savedViewToken, DeletionToken: deletionToken, Logger: logger, DatabaseProbe: databaseProbe, RecentEvents: databaseSink, LiveEvents: databaseSink, EventSnapshots: databaseSink, SavedViews: optionalSavedViewRepository(savedViews), CaptureDeletions: captureDeletions, SelectionDeletions: selectionDeletions, Forwarders: forwarders, Detections: detections}
	if cloudMetadata != nil {
		// Assign only a real client: a nil *LocalMetadataClient stored in the
		// interface field would look configured and fail every event.
		serverConfig.CloudMetadata = cloudMetadata
	}
	server, err := ingestserver.New(serverConfig)
	if err != nil {
		logger.Error("ingest server configuration rejected", "error", err)
		os.Exit(1)
	}
	coreHandler := server.Handler()
	rootHandler := http.NewServeMux()
	rootHandler.Handle("GET /v1/http-activity", server.HTTPActivityHandler())
	rootHandler.Handle("GET /v1/device-activity", server.DeviceActivityHandler())
	rootHandler.Handle("/", coreHandler)
	httpServer := &http.Server{Addr: envOr("SHAKERPROXY_INGEST_BIND", "127.0.0.1:8081"), Handler: rootHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if database != nil {
		defer database.Close()
		go runDatabaseDrain(ctx, logger, spool, databaseSink, savedViews)
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	logger.Info("ingestd starting", "bind", httpServer.Addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("ingestd stopped", "error", err)
		os.Exit(1)
	}
}

func runDatabaseDrain(ctx context.Context, logger *slog.Logger, spool *ingest.Spool, sink ingest.PostgresSink, savedViews *savedview.PostgresStore) {
	backoff := 250 * time.Millisecond
	migrated := false
	backfillDone := false
	for ctx.Err() == nil {
		if !migrated {
			// Schema upgrades may build indexes over existing history.
			migrationContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
			err := sink.Migrate(migrationContext)
			if err == nil && savedViews != nil {
				err = savedViews.Migrate(migrationContext)
			}
			cancel()
			if err != nil {
				logger.Warn("normalized event schema unavailable", "error", err, "retry_in", backoff.String())
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			migrated = true
			backoff = 250 * time.Millisecond
			logger.Info("PostgreSQL normalized event sink ready")
		}
		result, err := ingest.DrainOnce(ctx, spool, sink, 256)
		if err != nil {
			logger.Warn("normalized event drain paused", "error", err, "attempted", result.Attempted, "retry_in", backoff.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = 250 * time.Millisecond
		if result.Rejected > 0 || result.Purged > 0 {
			logger.Warn("normalized event records set aside so the backlog can drain", "rejected", result.Rejected, "purged", result.Purged, "reason", result.SetAsideReason)
			continue
		}
		if result.Committed > 0 {
			logger.Info("normalized event batch committed", "records", result.Committed)
			continue
		}
		if !backfillDone {
			backfillDone = runProjectionBackfill(ctx, logger, sink)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// runProjectionBackfill classifies one bounded batch of rows stored before
// protocol discovery existed, only while the drain is idle. It reports true
// once nothing is left in the backfill horizon.
func runProjectionBackfill(ctx context.Context, logger *slog.Logger, sink ingest.PostgresSink) bool {
	backfillContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	projected, err := sink.BackfillProjection(backfillContext, time.Now().UTC().Add(-ingest.ProjectionBackfillHorizon), 500)
	if err != nil {
		logger.Warn("protocol projection backfill paused", "error", err)
		return false
	}
	if projected == 0 {
		logger.Info("protocol projection backfill complete")
		return true
	}
	logger.Info("protocol projection backfilled", "records", projected)
	return false
}

func loadDatabaseURL(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 16 || info.Size() > 4096 {
		return "", errors.New("database URL file is unavailable or unsafe")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	url := strings.TrimSpace(string(value))
	parsed, parseErr := urlpkg.Parse(url)
	if parseErr != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" || parsed.User == nil || parsed.User.Username() == "" || parsed.Fragment != "" {
		return "", errors.New("database URL must use the PostgreSQL scheme")
	}
	return url, nil
}

func optionalSavedViewRepository(store *savedview.PostgresStore) savedview.Repository {
	if store == nil {
		return nil
	}
	return store
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
