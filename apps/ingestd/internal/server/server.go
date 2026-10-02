package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/cloudconnector"
	"shakerproxy.dev/shakerproxy/internal/detection"
	"shakerproxy.dev/shakerproxy/internal/forwarder"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/savedview"
	"shakerproxy.dev/shakerproxy/internal/secretfile"
)

type Config struct {
	Spool              *ingest.Spool
	Token              []byte
	QueryToken         []byte
	SavedViewToken     []byte
	DeletionToken      []byte
	Logger             *slog.Logger
	DatabaseProbe      func(context.Context) error
	RecentEvents       ingest.RecentEventReader
	LiveEvents         ingest.LiveEventReader
	EventSnapshots     ingest.EventQuerySnapshotRepository
	SavedViews         savedview.Repository
	CaptureDeletions   CaptureEventDeletionLifecycle
	SelectionDeletions EventSelectionDeletionLifecycle
	Forwarders         *forwarder.Manager
	Detections         *detection.Manager
	CloudMetadata      cloudMetadataQueue
}

type cloudMetadataQueue interface {
	Enqueue(context.Context, []cloudconnector.LocalMetadataEvent) error
}

type Server struct {
	cloudConnectorAbsent atomic.Bool
	spool                *ingest.Spool
	token                []byte
	queryToken           []byte
	savedViewToken       []byte
	deletionToken        []byte
	logger               *slog.Logger
	databaseProbe        func(context.Context) error
	recentEvents         ingest.RecentEventReader
	liveEvents           ingest.LiveEventReader
	eventSnapshots       ingest.EventQuerySnapshotRepository
	savedViews           savedview.Repository
	captureDeletions     CaptureEventDeletionLifecycle
	selectionDeletions   EventSelectionDeletionLifecycle
	forwarders           *forwarder.Manager
	detections           *detection.Manager
	cloudMetadata        cloudMetadataQueue
}

func New(config Config) (*Server, error) {
	if config.Spool == nil || !validToken(config.Token) || !validToken(config.QueryToken) {
		return nil, errors.New("ingest spool and distinct 32-to-128-byte ingest and query tokens are required")
	}
	if len(config.Token) == len(config.QueryToken) && subtle.ConstantTimeCompare(config.Token, config.QueryToken) == 1 {
		return nil, errors.New("ingest and event query tokens must differ")
	}
	if config.SavedViews != nil {
		if !validToken(config.SavedViewToken) || sameToken(config.SavedViewToken, config.Token) || sameToken(config.SavedViewToken, config.QueryToken) {
			return nil, errors.New("saved view storage requires a distinct 32-to-128-byte token")
		}
	}
	if config.CaptureDeletions != nil || config.SelectionDeletions != nil {
		if !validToken(config.DeletionToken) || sameToken(config.DeletionToken, config.Token) || sameToken(config.DeletionToken, config.QueryToken) || sameToken(config.DeletionToken, config.SavedViewToken) {
			return nil, errors.New("capture event deletion requires a distinct 32-to-128-byte token")
		}
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{spool: config.Spool, token: append([]byte(nil), config.Token...), queryToken: append([]byte(nil), config.QueryToken...), savedViewToken: append([]byte(nil), config.SavedViewToken...), deletionToken: append([]byte(nil), config.DeletionToken...), logger: logger, databaseProbe: config.DatabaseProbe, recentEvents: config.RecentEvents, liveEvents: config.LiveEvents, eventSnapshots: config.EventSnapshots, savedViews: config.SavedViews, captureDeletions: config.CaptureDeletions, selectionDeletions: config.SelectionDeletions, forwarders: config.Forwarders, detections: config.Detections, cloudMetadata: config.CloudMetadata}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("POST /v1/events", s.requireToken(http.HandlerFunc(s.acceptEvent)))
	mux.Handle("GET /v1/events", s.requireQueryToken(http.HandlerFunc(s.listRecentEvents)))
	mux.Handle("GET /v1/events/{recordID}", s.requireQueryToken(http.HandlerFunc(s.getEventDetail)))
	mux.Handle("GET /v1/events/live-batch", s.requireQueryToken(http.HandlerFunc(s.listLiveEvents)))
	mux.Handle("GET /v1/query-stats", s.requireQueryToken(http.HandlerFunc(s.queryStats)))
	mux.Handle("GET /v1/protocol-summary", s.requireQueryToken(http.HandlerFunc(s.listProtocolSummary)))
	mux.Handle("GET /v1/device-platform-hints", s.requireQueryToken(http.HandlerFunc(s.listDevicePlatformHints)))
	if s.eventSnapshots != nil {
		mux.Handle("POST /v1/event-query-snapshots", s.requireQueryToken(http.HandlerFunc(s.createEventQuerySnapshot)))
		mux.Handle("GET /v1/event-query-snapshots/{snapshotID}", s.requireQueryToken(http.HandlerFunc(s.getEventQuerySnapshot)))
	}
	if s.savedViews != nil {
		mux.Handle("GET /v1/saved-views", s.requireSavedViewToken(http.HandlerFunc(s.listSavedViews)))
		mux.Handle("POST /v1/saved-views", s.requireSavedViewToken(http.HandlerFunc(s.createSavedView)))
		mux.Handle("GET /v1/saved-views/{viewID}", s.requireSavedViewToken(http.HandlerFunc(s.getSavedView)))
		mux.Handle("PUT /v1/saved-views/{viewID}", s.requireSavedViewToken(http.HandlerFunc(s.updateSavedView)))
		mux.Handle("DELETE /v1/saved-views/{viewID}", s.requireSavedViewToken(http.HandlerFunc(s.deleteSavedView)))
		mux.Handle("GET /v1/saved-views/{viewID}/history", s.requireSavedViewToken(http.HandlerFunc(s.savedViewHistory)))
	}
	if s.captureDeletions != nil {
		mux.Handle("POST /v1/capture-event-deletions/{sessionID}/preview", s.requireDeletionToken(http.HandlerFunc(s.previewCaptureEventDeletion)))
		mux.Handle("POST /v1/capture-event-deletions/{sessionID}/execute", s.requireDeletionToken(http.HandlerFunc(s.executeCaptureEventDeletion)))
	}
	if s.selectionDeletions != nil {
		mux.Handle("POST /v1/event-selection-deletions/preview", s.requireDeletionToken(http.HandlerFunc(s.previewEventSelectionDeletion)))
		mux.Handle("POST /v1/event-selection-deletions/execute", s.requireDeletionToken(http.HandlerFunc(s.executeEventSelectionDeletion)))
	}
	mux.Handle("POST /v1/adapters/zeek", s.requireToken(http.HandlerFunc(s.acceptZeek)))
	mux.Handle("POST /v1/adapters/suricata", s.requireToken(http.HandlerFunc(s.acceptSuricata)))
	mux.Handle("POST /v1/adapters/zeek/batch", s.requireToken(http.HandlerFunc(s.acceptZeekBatch)))
	mux.Handle("POST /v1/adapters/suricata/batch", s.requireToken(http.HandlerFunc(s.acceptSuricataBatch)))
	mux.Handle("GET /v1/stats", s.requireToken(http.HandlerFunc(s.stats)))
	return securityHeaders(mux)
}

func (s *Server) getEventDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "event detail does not accept query parameters")
		return
	}
	reader, ok := s.recentEvents.(ingest.EventDetailReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "event_detail_unavailable", "normalized event detail storage is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	detail, err := reader.GetEventDetail(ctx, r.PathValue("recordID"))
	if errors.Is(err, ingest.ErrEventNotFound) {
		writeError(w, http.StatusNotFound, "event_not_found", "normalized event was not found")
		return
	}
	if err != nil {
		s.logger.Warn("normalized event detail query failed", "record_id", r.PathValue("recordID"), "error", err)
		writeError(w, http.StatusServiceUnavailable, "event_detail_unavailable", "normalized event detail is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) listLiveEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := ingest.ParseInternalLiveEventQuery(r.URL.Query(), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	if s.liveEvents == nil {
		writeError(w, http.StatusServiceUnavailable, "event_store_unavailable", "live normalized event storage is unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	batch, err := s.liveEvents.QueryAfter(queryContext, query)
	if err != nil {
		s.logger.Warn("live normalized event query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "event_store_unavailable", "live normalized events are temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, batch)
}

func (s *Server) queryStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s.stats(w, r)
}

func (s *Server) listRecentEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := ingest.ParseInternalRecentEventQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	if s.recentEvents == nil {
		writeError(w, http.StatusServiceUnavailable, "event_store_unavailable", "normalized event storage is unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	page, err := s.recentEvents.QueryRecent(queryContext, query)
	if err != nil {
		s.logger.Warn("recent normalized event query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "event_store_unavailable", "normalized events are temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	stats, err := s.spool.QuickStats()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	status := "ok"
	databaseConnected := false
	if s.databaseProbe != nil {
		probeContext, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		databaseConnected = s.databaseProbe(probeContext) == nil
		cancel()
	}
	if stats.StoragePressure || (s.databaseProbe != nil && !databaseConnected) {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "storage_pressure": stats.StoragePressure, "database_configured": s.databaseProbe != nil, "database_connected": databaseConnected})
}

func (s *Server) acceptEvent(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content_type_required", "Content-Type must be application/json")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, ingest.MaxEventBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read_failed", "event body could not be read")
		return
	}
	if len(raw) > ingest.MaxEventBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "event_too_large", "event exceeds the byte limit")
		return
	}
	result, err := s.spool.Accept(raw)
	if err != nil {
		if errors.Is(err, ingest.ErrCaptureTombstoned) {
			writeError(w, http.StatusGone, "capture_deleted", "capture-derived events are no longer accepted")
			return
		}
		if errors.Is(err, ingest.ErrEventSelectionTombstoned) {
			writeError(w, http.StatusGone, "event_selection_deleted", "events in this deleted device/time selection are no longer accepted")
			return
		}
		s.logger.Warn("ingest event rejected by spool", "error", err)
		writeError(w, http.StatusInsufficientStorage, "spool_unavailable", err.Error())
		return
	}
	if result.Accepted && !result.Duplicate {
		if envelope, decodeErr := ingest.DecodeEnvelope(raw); decodeErr == nil {
			if s.forwarders != nil {
				if forwardErr := s.forwarders.Enqueue(envelope); forwardErr != nil {
					s.logger.Error("safe event forwarding enqueue failed", "event_id", envelope.EventID, "error", forwardErr)
				}
			}
			if detectionErr := s.emitDetections(envelope); detectionErr != nil {
				s.logger.Error("native detection evaluation failed", "event_id", envelope.EventID, "error", detectionErr)
			}
		}
	}
	if result.Accepted {
		if envelope, decodeErr := ingest.DecodeEnvelope(raw); decodeErr == nil {
			if err := s.enqueueCloudMetadata(r.Context(), envelope); err != nil {
				s.logger.Warn("cloud metadata queue unavailable; source should retry", "event_id", envelope.EventID, "error", err)
				writeError(w, http.StatusServiceUnavailable, "cloud_queue_unavailable", "event is safe locally but cloud queueing must be retried")
				return
			}
		}
	}
	s.writeAcceptResult(w, result)
}

func (s *Server) acceptZeek(w http.ResponseWriter, r *http.Request) {
	s.acceptAdapter(w, r, ingest.NormalizeZeekJSON)
}

func (s *Server) acceptSuricata(w http.ResponseWriter, r *http.Request) {
	s.acceptAdapter(w, r, ingest.NormalizeSuricataEVE)
}

func (s *Server) acceptAdapter(w http.ResponseWriter, r *http.Request, normalize func([]byte, string, string) (ingest.Envelope, error)) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content_type_required", "Content-Type must be application/json")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, ingest.MaxPayloadBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read_failed", "adapter body could not be read")
		return
	}
	if len(raw) > ingest.MaxPayloadBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "event_too_large", "adapter event exceeds the byte limit")
		return
	}
	envelope, normalizeErr := normalize(raw, r.Header.Get("X-ShakerProxy-Source-Version"), r.Header.Get("X-ShakerProxy-Capture-Session-ID"))
	if normalizeErr != nil {
		result, quarantineErr := s.spool.Quarantine(raw, normalizeErr.Error())
		if quarantineErr != nil {
			writeError(w, http.StatusInsufficientStorage, "spool_unavailable", quarantineErr.Error())
			return
		}
		s.writeAcceptResult(w, result)
		return
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "normalization_failed", "normalized event could not be encoded")
		return
	}
	result, err := s.spool.Accept(encoded)
	if err != nil {
		if errors.Is(err, ingest.ErrCaptureTombstoned) {
			writeError(w, http.StatusGone, "capture_deleted", "capture-derived events are no longer accepted")
			return
		}
		if errors.Is(err, ingest.ErrEventSelectionTombstoned) {
			writeError(w, http.StatusGone, "event_selection_deleted", "events in this deleted device/time selection are no longer accepted")
			return
		}
		writeError(w, http.StatusInsufficientStorage, "spool_unavailable", err.Error())
		return
	}
	if result.Accepted && !result.Duplicate && s.forwarders != nil {
		if forwardErr := s.forwarders.Enqueue(envelope); forwardErr != nil {
			s.logger.Error("safe event forwarding enqueue failed", "event_id", envelope.EventID, "error", forwardErr)
		}
	}
	if result.Accepted && !result.Duplicate {
		if detectionErr := s.emitDetections(envelope); detectionErr != nil {
			s.logger.Error("native detection evaluation failed", "event_id", envelope.EventID, "error", detectionErr)
		}
	}
	if result.Accepted {
		if err := s.enqueueCloudMetadata(r.Context(), envelope); err != nil {
			s.logger.Warn("cloud metadata queue unavailable; analyzer should retry", "event_id", envelope.EventID, "error", err)
			writeError(w, http.StatusServiceUnavailable, "cloud_queue_unavailable", "event is safe locally but cloud queueing must be retried")
			return
		}
	}
	s.writeAcceptResult(w, result)
}

func (s *Server) acceptZeekBatch(w http.ResponseWriter, r *http.Request) {
	s.acceptAdapterBatch(w, r, ingest.NormalizeZeekJSON)
}

func (s *Server) acceptSuricataBatch(w http.ResponseWriter, r *http.Request) {
	s.acceptAdapterBatch(w, r, ingest.NormalizeSuricataEVE)
}

// adapterBatchResult answers a batch with one result per event line, in order.
type adapterBatchResult struct {
	Schema  int                   `json:"schema"`
	Results []ingest.AcceptResult `json:"results"`
}

// acceptAdapterBatch takes one analyzer output line per NDJSON line and
// stores them with one round of disk syncs (Spool.AcceptBatch). Each event is
// normalized, deduplicated, quarantined, forwarded and checked for detections
// exactly as on the one-event route; only the durability work is shared.
func (s *Server) acceptAdapterBatch(w http.ResponseWriter, r *http.Request, normalize func([]byte, string, string) (ingest.Envelope, error)) {
	if r.Header.Get("Content-Type") != "application/x-ndjson" {
		writeError(w, http.StatusUnsupportedMediaType, "content_type_required", "Content-Type must be application/x-ndjson")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, ingest.MaxAdapterBatchBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read_failed", "adapter batch could not be read")
		return
	}
	if len(raw) > ingest.MaxAdapterBatchBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "batch_too_large", "adapter batch exceeds the byte limit")
		return
	}
	lines := make([][]byte, 0, 64)
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			continue
		}
		if len(line) > ingest.MaxPayloadBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "event_too_large", "an adapter event exceeds the byte limit")
			return
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 || len(lines) > ingest.MaxAcceptBatchRecords {
		writeError(w, http.StatusRequestEntityTooLarge, "batch_size_invalid", "an adapter batch holds 1 to "+strconv.Itoa(ingest.MaxAcceptBatchRecords)+" events")
		return
	}
	sourceVersion, captureSessionID := r.Header.Get("X-ShakerProxy-Source-Version"), r.Header.Get("X-ShakerProxy-Capture-Session-ID")
	results := make([]ingest.AcceptResult, len(lines))
	envelopes := make([]ingest.Envelope, 0, len(lines))
	encoded := make([][]byte, 0, len(lines))
	positions := make([]int, 0, len(lines))
	for index, line := range lines {
		envelope, normalizeErr := normalize(line, sourceVersion, captureSessionID)
		if normalizeErr != nil {
			result, quarantineErr := s.spool.Quarantine(line, normalizeErr.Error())
			if quarantineErr != nil {
				writeError(w, http.StatusInsufficientStorage, "spool_unavailable", quarantineErr.Error())
				return
			}
			results[index] = result
			continue
		}
		data, marshalErr := json.Marshal(envelope)
		if marshalErr != nil {
			writeError(w, http.StatusInternalServerError, "normalization_failed", "normalized event could not be encoded")
			return
		}
		envelopes = append(envelopes, envelope)
		encoded = append(encoded, data)
		positions = append(positions, index)
	}
	var accepted []ingest.AcceptResult
	var acceptErr error
	if len(encoded) > 0 {
		accepted, acceptErr = s.spool.AcceptBatch(encoded)
	}
	// Events committed before a failing one are stored; forward them and
	// check them for detections now, because a retry only sees duplicates.
	for index, result := range accepted {
		results[positions[index]] = result
		if !result.Accepted || result.Duplicate {
			continue
		}
		if s.forwarders != nil {
			if forwardErr := s.forwarders.Enqueue(envelopes[index]); forwardErr != nil {
				s.logger.Error("safe event forwarding enqueue failed", "event_id", envelopes[index].EventID, "error", forwardErr)
			}
		}
		if detectionErr := s.emitDetections(envelopes[index]); detectionErr != nil {
			s.logger.Error("native detection evaluation failed", "event_id", envelopes[index].EventID, "error", detectionErr)
		}
	}
	if acceptErr != nil {
		switch {
		case errors.Is(acceptErr, ingest.ErrCaptureTombstoned):
			writeError(w, http.StatusGone, "capture_deleted", "capture-derived events are no longer accepted")
		case errors.Is(acceptErr, ingest.ErrEventSelectionTombstoned):
			writeError(w, http.StatusGone, "event_selection_deleted", "events in this deleted device/time selection are no longer accepted")
		default:
			writeError(w, http.StatusInsufficientStorage, "spool_unavailable", acceptErr.Error())
		}
		return
	}
	for index, result := range accepted {
		if !result.Accepted {
			continue
		}
		if err := s.enqueueCloudMetadata(r.Context(), envelopes[index]); err != nil {
			s.logger.Warn("cloud metadata queue unavailable; analyzer should retry", "event_id", envelopes[index].EventID, "error", err)
			writeError(w, http.StatusServiceUnavailable, "cloud_queue_unavailable", "events are safe locally but cloud queueing must be retried")
			return
		}
	}
	for _, result := range results {
		if result.Quarantined {
			s.logger.Warn("ingest event quarantined", "record_id", result.RecordID, "reason", result.Reason)
		}
	}
	writeJSON(w, http.StatusOK, adapterBatchResult{Schema: ingest.SchemaVersion, Results: results})
}

func (s *Server) enqueueCloudMetadata(ctx context.Context, envelope ingest.Envelope) error {
	if s.cloudMetadata == nil {
		return nil
	}
	events := cloudconnector.ProjectNormalizedEvents(envelope, time.Now().UTC())
	if len(events) == 0 {
		return nil
	}
	err := s.cloudMetadata.Enqueue(ctx, events)
	if err != nil && cloudConnectorNotRunning(err) {
		// The cloud connector is optional. When it is not running, local
		// ingestion continues and cloud copies of these events are skipped;
		// only a running connector that cannot queue asks sources to retry.
		if s.cloudConnectorAbsent.CompareAndSwap(false, true) {
			s.logger.Info("cloud connector is not running; continuing with local ingestion only", "error", err)
		}
		return nil
	}
	if err == nil && s.cloudConnectorAbsent.CompareAndSwap(true, false) {
		s.logger.Info("cloud connector is available again; queueing cloud metadata")
	}
	return err
}

func cloudConnectorNotRunning(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}

func (s *Server) emitDetections(envelope ingest.Envelope) error {
	if s.detections == nil || strings.HasPrefix(envelope.Kind, "shakerproxy.detection.") {
		return nil
	}
	for _, observation := range s.detections.ObservationsFromEnvelope(envelope) {
		events, err := s.detections.Observe(observation)
		if err != nil {
			return err
		}
		for _, event := range events {
			payload, err := json.Marshal(event)
			if err != nil {
				return err
			}
			derived := ingest.Envelope{Schema: ingest.SchemaVersion, EventID: event.ID, Source: ingest.SourceHost, Kind: "shakerproxy.detection." + strings.ToLower(string(event.Type)), OccurredAt: event.LastSeenAt, SourceVersion: "shakerproxy-native-v1", ParserVersion: "shakerproxy-detection-v1", Confidence: 95, Payload: payload}
			encoded, err := json.Marshal(derived)
			if err != nil {
				return err
			}
			result, err := s.spool.Accept(encoded)
			if err != nil {
				return err
			}
			if result.Accepted && !result.Duplicate && s.forwarders != nil {
				if err := s.forwarders.Enqueue(derived); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Server) writeAcceptResult(w http.ResponseWriter, result ingest.AcceptResult) {
	if result.Quarantined {
		s.logger.Warn("ingest event quarantined", "record_id", result.RecordID, "reason", result.Reason)
		writeJSON(w, http.StatusUnprocessableEntity, result)
		return
	}
	status := http.StatusAccepted
	if result.Duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, result)
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.spool.Stats()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "spool_unavailable", "ingestion spool is unavailable")
		return
	}
	stats.DatabaseConfigured = s.databaseProbe != nil
	if s.databaseProbe != nil {
		probeContext, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		stats.DatabaseConnected = s.databaseProbe(probeContext) == nil
		cancel()
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) requireToken(next http.Handler) http.Handler {
	return requireBearer(s.token, "valid ingest authentication is required", next)
}

func (s *Server) requireQueryToken(next http.Handler) http.Handler {
	return requireBearer(s.queryToken, "valid event query authentication is required", next)
}

func (s *Server) requireSavedViewToken(next http.Handler) http.Handler {
	return requireBearer(s.savedViewToken, "valid saved view storage authentication is required", next)
}

func (s *Server) requireDeletionToken(next http.Handler) http.Handler {
	return requireBearer(s.deletionToken, "valid capture event deletion authentication is required", next)
}

func sameToken(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func requireBearer(token []byte, message string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		provided := strings.TrimPrefix(header, "Bearer ")
		if !strings.HasPrefix(header, "Bearer ") || len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), token) != 1 {
			writeError(w, http.StatusUnauthorized, "authentication_required", message)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validToken(token []byte) bool {
	if len(token) < 32 || len(token) > 128 {
		return false
	}
	for _, char := range token {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func LoadToken(path string) ([]byte, error) {
	b, err := secretfile.LoadToken(path)
	if err != nil {
		return nil, errors.New("ingest token file is unavailable or unsafe")
	}
	return b, nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
