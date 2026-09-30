package ingest

import (
	"fmt"
	"strings"
)

// insertColumn binds one normalized_events column to a placeholder
// expression. "%s" in expression is replaced with the positional parameter.
type insertColumn struct {
	name       string
	expression string
	value      any
}

type insertColumns []insertColumn

func (columns insertColumns) insertStatement() string {
	names := make([]string, 0, len(columns)+1)
	values := make([]string, 0, len(columns)+1)
	parameter := 0
	for _, column := range columns {
		names = append(names, column.name)
		if column.expression == "" {
			// A literal SQL expression without a parameter.
			values = append(values, fmt.Sprint(column.value))
			continue
		}
		parameter++
		values = append(values, strings.ReplaceAll(column.expression, "%s", fmt.Sprintf("$%d", parameter)))
	}
	return "INSERT INTO normalized_events(" + strings.Join(names, ", ") + ") VALUES (" + strings.Join(values, ",") + ") ON CONFLICT (occurred_at, record_id) DO NOTHING"
}

func (columns insertColumns) args() []any {
	args := make([]any, 0, len(columns))
	for _, column := range columns {
		if column.expression != "" {
			args = append(args, column.value)
		}
	}
	return args
}

// projectionColumns are the columns ProjectEvent owns. Inserts write them and
// the backfill rewrites them for rows stored before they existed.
func projectionColumns(projection EventProjection) insertColumns {
	network, dns, detection, tls, http, alert, protocol := projection.Network, projection.DNS, projection.Detection, projection.TLS, projection.HTTP, projection.Alert, projection.Protocol
	var tlsClientRecentSuccess, tlsPinning, tlsBypass any
	if tls.ClientRecentSuccess != nil {
		tlsClientRecentSuccess = *tls.ClientRecentSuccess
	}
	if tls.InterceptionState != "" {
		// TLS outcome events store explicit booleans so that
		// tls.pinning:false matches them instead of nothing.
		tlsPinning, tlsBypass = tls.PinningSuspected, tls.DynamicBypassActivated
	}
	var exotic any
	if protocol.Present() {
		exotic = protocol.Exotic
	}
	return insertColumns{
		{"source_ip", "NULLIF(%s,'')::inet", network.SourceIP},
		{"destination_ip", "NULLIF(%s,'')::inet", network.DestinationIP},
		{"source_port", "NULLIF(%s,0)", network.SourcePort},
		{"destination_port", "NULLIF(%s,0)", network.DestinationPort},
		{"protocol", "NULLIF(%s,'')", network.Protocol},
		{"service", "NULLIF(%s,'')", network.Service},
		{"network_bytes", "NULLIF(%s::bigint,0)", network.NetworkBytes},
		{"dns_query", "NULLIF(%s,'')", dns.Query},
		{"dns_record_type", "NULLIF(%s,'')", dns.RecordType},
		{"dns_response_code", "NULLIF(%s,'')", dns.ResponseCode},
		{"dns_answer_count", "%s", dns.AnswerCount},
		{"detection_type", "NULLIF(%s,'')", detection.Type},
		{"detection_severity", "NULLIF(%s,'')", detection.Severity},
		{"detection_state", "NULLIF(%s,'')", detection.State},
		{"detection_summary", "NULLIF(%s,'')", detection.Summary},
		{"detection_scope", "NULLIF(%s,'')", detection.Scope},
		{"tls_server_name", "NULLIF(%s,'')", tls.ServerName},
		{"tls_interception_state", "NULLIF(%s,'')", tls.InterceptionState},
		{"tls_failure_reason", "NULLIF(%s,'')", tls.FailureReason},
		{"tls_pinning_suspected", "%s::boolean", tlsPinning},
		{"tls_client_recent_success", "%s::boolean", tlsClientRecentSuccess},
		{"tls_bypass_activated", "%s::boolean", tlsBypass},
		{"tls_platform", "NULLIF(%s,'')", tls.Platform},
		{"http_method", "NULLIF(%s,'')", http.Method},
		{"http_host", "NULLIF(%s,'')", http.Host},
		{"http_path", "NULLIF(%s,'')", http.Path},
		{"http_status", "NULLIF(%s::smallint,0)", http.Status},
		{"alert_signature", "NULLIF(%s,'')", alert.Signature},
		{"alert_severity", "NULLIF(%s::smallint,0)", alert.Severity},
		{"alert_category", "NULLIF(%s,'')", alert.Category},
		{"app_protocol", "NULLIF(%s,'')", protocol.AppProtocol},
		{"protocol_category", "NULLIF(%s,'')", protocol.Category},
		{"protocol_visibility", "NULLIF(%s,'')", protocol.Visibility},
		{"protocol_evidence", "NULLIF(%s,'')", protocol.Evidence},
		{"protocol_exotic", "%s::boolean", exotic},
		{"projection_version", "%s::smallint", ProjectionVersion},
	}
}

func normalizedEventColumns(pending PendingRecord, envelope Envelope, projection EventProjection, attributionJSON string) insertColumns {
	record := pending.Record
	columns := insertColumns{
		{"record_id", "%s", pending.RecordID},
		{"event_sha256", "%s", record.EventSHA256},
		{"source", "%s", envelope.Source},
		{"kind", "%s", envelope.Kind},
		{"occurred_at", "%s", envelope.OccurredAt},
		{"received_at", "", "clock_timestamp()"},
		{"source_version", "%s", envelope.SourceVersion},
		{"parser_version", "%s", envelope.ParserVersion},
		{"capture_session_id", "NULLIF(%s,'')", envelope.CaptureSessionID},
		{"flow_id", "NULLIF(%s,'')", envelope.FlowID},
		{"device_id", "NULLIF(%s,'')", envelope.DeviceID},
		{"confidence", "%s", envelope.Confidence},
	}
	columns = append(columns, projectionColumns(projection)...)
	return append(columns,
		insertColumn{"attribution_evidence", "NULLIF(%s,'')::jsonb", attributionJSON},
		insertColumn{"payload", "%s", string(envelope.Payload)},
	)
}
