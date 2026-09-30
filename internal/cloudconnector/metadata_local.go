package cloudconnector

import (
	"net/http"
	"strings"
)

func (s LocalServer) metadataStatus(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeLocalError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	if s.MetadataQueue == nil {
		writeLocalError(w, http.StatusServiceUnavailable, "metadata_queue_unavailable")
		return
	}
	summary, err := s.MetadataQueue.Summary()
	if err != nil {
		writeLocalError(w, http.StatusInternalServerError, "metadata_queue_unavailable")
		return
	}
	writeLocalJSON(w, http.StatusOK, summary)
}

func (s LocalServer) enqueueMetadata(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeLocalError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	if s.MetadataQueue == nil {
		writeLocalError(w, http.StatusServiceUnavailable, "metadata_queue_unavailable")
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeLocalError(w, http.StatusUnsupportedMediaType, "json_required")
		return
	}
	events, err := decodeMetadataEnqueue(r.Body, 2<<20)
	if err != nil {
		writeLocalError(w, http.StatusBadRequest, "invalid_metadata")
		return
	}
	for _, event := range events {
		// Protocol summaries are produced only by the connector's own rollup,
		// which gates them on the cloud's advertised capability.
		if event.Type == MetadataProtocolSummary {
			writeLocalError(w, http.StatusBadRequest, "invalid_metadata")
			return
		}
	}
	if s.DeviceRuntime != nil {
		if err := s.DeviceRuntime.ObserveMetadata(events); err != nil {
			writeLocalError(w, http.StatusBadRequest, "device_runtime_rejected")
			return
		}
	}
	added, err := s.MetadataQueue.enqueue(events)
	if err != nil {
		writeLocalError(w, http.StatusBadRequest, "metadata_rejected")
		return
	}
	if s.ProtocolRollup != nil && len(added) != 0 {
		// Best effort: the rollup is derived data and must never make the
		// analyzer retry an event that is already safely queued.
		_ = s.ProtocolRollup.Observe(added)
	}
	summary, _ := s.MetadataQueue.Summary()
	writeLocalJSON(w, http.StatusAccepted, map[string]any{
		"accepted": len(events),
		"queue":    summary,
	})
}
