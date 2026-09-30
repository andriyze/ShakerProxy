package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func (s *Server) openMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "metrics does not accept query parameters")
		return
	}
	var output bytes.Buffer
	output.WriteString("# HELP shakerproxy_gateway_available Whether the privileged gateway status was readable.\n# TYPE shakerproxy_gateway_available gauge\n")
	requestContext, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	var gateway gatewayprotocol.Status
	if err := s.gateway.Call(requestContext, "GetManagedState", gatewayprotocol.EmptyParams{}, &gateway); err == nil {
		output.WriteString("shakerproxy_gateway_available 1\n")
		fmt.Fprintf(&output, "shakerproxy_emergency_bypass %d\n", metricBool(gateway.EmergencyBypass))
		fmt.Fprintf(&output, "shakerproxy_capture_active %d\n", metricBool(gateway.ActiveCaptureID != ""))
	} else {
		output.WriteString("shakerproxy_gateway_available 0\n")
	}
	output.WriteString("# HELP shakerproxy_ingest_available Whether bounded ingestion status was readable.\n# TYPE shakerproxy_ingest_available gauge\n")
	if s.ingestStatus != nil {
		ingestContext, ingestCancel := context.WithTimeout(r.Context(), 2*time.Second)
		stats, err := s.ingestStatus.IngestStatus(ingestContext)
		ingestCancel()
		if err == nil {
			output.WriteString("shakerproxy_ingest_available 1\n")
			fmt.Fprintf(&output, "shakerproxy_ingest_pending_records %d\nshakerproxy_ingest_pending_bytes %d\nshakerproxy_ingest_storage_pressure %d\nshakerproxy_ingest_database_connected %d\n", stats.PendingRecords, stats.PendingBytes, metricBool(stats.StoragePressure), metricBool(stats.DatabaseConnected))
		} else {
			output.WriteString("shakerproxy_ingest_available 0\n")
		}
	} else {
		output.WriteString("shakerproxy_ingest_available 0\n")
	}
	output.WriteString("# HELP shakerproxy_forwarder_queued Metadata-only events awaiting delivery.\n# TYPE shakerproxy_forwarder_queued gauge\n")
	if s.forwarders != nil {
		if statuses, err := s.forwarders.Status(); err == nil {
			for _, status := range statuses {
				labels := fmt.Sprintf("forwarder_id=\"%s\",transport=\"%s\"", status.Integration.ID, status.Integration.Kind)
				fmt.Fprintf(&output, "shakerproxy_forwarder_enabled{%s} %d\nshakerproxy_forwarder_queued{%s} %d\nshakerproxy_forwarder_delivered_total{%s} %d\nshakerproxy_forwarder_dropped_total{%s} %d\n", labels, metricBool(status.Integration.Enabled), labels, status.Queued, labels, status.Delivered, labels, status.Dropped)
			}
		}
	}
	output.WriteString("# EOF\n")
	w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output.Bytes())
}

func metricBool(value bool) int {
	if value {
		return 1
	}
	return 0
}
