package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

const (
	livePollInterval = 750 * time.Millisecond
	liveHeartbeat    = 15 * time.Second
	liveWriteTimeout = 5 * time.Second
)

func (s *Server) streamLiveEvents(w http.ResponseWriter, r *http.Request) {
	if s.liveEventReader == nil {
		writeError(w, http.StatusServiceUnavailable, "event_stream_unavailable", "live normalized event streaming is not configured")
		return
	}
	query, err := ingest.ParseLiveEventQuery(r.URL.Query(), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	if err := s.resolveEventDeviceSelectors(&query.RecentEventQuery); err != nil {
		if errors.Is(err, inventory.ErrAliasResolutionLimit) {
			writeError(w, http.StatusUnprocessableEntity, "query_too_broad", "device selector query matches too many devices; use device.id to narrow it")
			return
		}
		s.logger.Warn("live device selector query resolution failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "device_selectors_unavailable", "device selector search is temporarily unavailable")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming_unsupported", "streaming is unavailable")
		return
	}
	select {
	case s.liveSlots <- struct{}{}:
		defer func() { <-s.liveSlots }()
	default:
		writeError(w, http.StatusTooManyRequests, "stream_limit_reached", "too many live event streams are active")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Time{})
	if !writeSSE(controller, w, flusher, ": connected\n\n") {
		return
	}

	poll := time.NewTicker(livePollInterval)
	defer poll.Stop()
	heartbeat := time.NewTicker(liveHeartbeat)
	defer heartbeat.Stop()
	for {
		queryContext, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		batch, queryErr := s.liveEventReader.QueryAfter(queryContext, query)
		cancel()
		if queryErr != nil {
			s.logger.Warn("live normalized event stream query failed", "error", queryErr)
			return
		}
		if len(batch.Events) > 0 {
			batch.DeviceLabelsAvailable = s.projectDeviceNames(batch.Events)
			encoded, marshalErr := json.Marshal(batch)
			if marshalErr != nil {
				return
			}
			frame := fmt.Sprintf("id: %s\nevent: events\ndata: %s\n\n", batch.NextCursor, encoded)
			if !writeSSE(controller, w, flusher, frame) {
				return
			}
			query.AfterReceivedAt, query.AfterRecordID, err = ingest.DecodeLiveEventCursor(batch.NextCursor)
			if err != nil {
				return
			}
		}
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if !writeSSE(controller, w, flusher, ": heartbeat\n\n") {
				return
			}
		case <-poll.C:
		}
	}
}

func writeSSE(controller *http.ResponseController, w http.ResponseWriter, flusher http.Flusher, frame string) bool {
	if controller.SetWriteDeadline(time.Now().Add(liveWriteTimeout)) != nil {
		return false
	}
	if _, err := fmt.Fprint(w, frame); err != nil {
		return false
	}
	flusher.Flush()
	return controller.SetWriteDeadline(time.Time{}) == nil
}
