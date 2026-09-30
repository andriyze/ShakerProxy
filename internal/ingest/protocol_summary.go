package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"time"

	"shakerproxy.dev/shakerproxy/internal/protocolclass"
)

// Protocol discovery bounds. The catalog is far smaller than
// MaxSummaryProtocols, but the response is bounded independently of it.
const (
	ProtocolSummarySchemaVersion   = 1
	MaxSummaryProtocols            = 256
	MaxSummaryDevicesPerProtocol   = 50
	MaxSummaryPortsPerProtocol     = 20
	MaxProtocolSummaryScannedRows  = 500_000
	DefaultProtocolSummaryWindow   = "24h"
	protocolSummaryCorrelationSkew = 10 * time.Minute
)

var protocolSummaryWindows = map[string]int{"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}

// ProtocolSummaryWindowSeconds maps a public window label to seconds.
func ProtocolSummaryWindowSeconds(label string) (int, bool) {
	seconds, ok := protocolSummaryWindows[label]
	return seconds, ok
}

func protocolSummaryWindowLabel(seconds int) string {
	for label, value := range protocolSummaryWindows {
		if value == seconds {
			return label
		}
	}
	return ""
}

// ProtocolSummaryQuery selects the protocol discovery aggregate.
type ProtocolSummaryQuery struct {
	WindowSeconds int
	DeviceID      string
	Category      string
	// Exotic, when set, keeps only exotic (true) or mainstream (false)
	// protocols. Coverage always describes every protocol in scope.
	Exotic *bool
}

type ProtocolSummary struct {
	Schema      int              `json:"schema"`
	GeneratedAt time.Time        `json:"generated_at"`
	Window      string           `json:"window"`
	WindowStart time.Time        `json:"window_start"`
	WindowEnd   time.Time        `json:"window_end"`
	DeviceID    string           `json:"device_id,omitempty"`
	Protocols   []ProtocolUsage  `json:"protocols"`
	Coverage    ProtocolCoverage `json:"coverage"`
	// Sources lists which analyzers contributed data in the window, so a
	// client can explain gaps ("start a capture for passive analysis").
	Sources   []Source `json:"sources"`
	Truncated bool     `json:"truncated"`
}

type ProtocolUsage struct {
	Protocol    string `json:"protocol"`
	Label       string `json:"label"`
	Category    string `json:"category"`
	Visibility  string `json:"visibility"`
	Evidence    string `json:"evidence"`
	Exotic      bool   `json:"exotic"`
	Novel       bool   `json:"novel"`
	Description string `json:"description"`
	Flows       int64  `json:"flows"`
	Bytes       int64  `json:"bytes"`
	// Events counts every record that identified the protocol, including
	// application-layer evidence (dns.log, http, alerts) that is not a flow.
	Events            int64                 `json:"events"`
	DeviceCount       int                   `json:"device_count"`
	Devices           []ProtocolDeviceUsage `json:"devices"`
	UnattributedFlows int64                 `json:"unattributed_flows"`
	FirstSeen         time.Time             `json:"first_seen"`
	LastSeen          time.Time             `json:"last_seen"`
	Ports             []ProtocolPortUsage   `json:"ports"`
}

type ProtocolDeviceUsage struct {
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name"`
	Flows      int64     `json:"flows"`
	Bytes      int64     `json:"bytes"`
	LastSeen   time.Time `json:"last_seen"`
}

type ProtocolPortUsage struct {
	Transport string `json:"transport"`
	Port      int    `json:"port"`
	Flows     int64  `json:"flows"`
}

type ProtocolCoverage struct {
	TotalBytes             int64   `json:"total_bytes"`
	DecryptedBytes         int64   `json:"decrypted_bytes"`
	CleartextBytes         int64   `json:"cleartext_bytes"`
	EncryptedMetadataBytes int64   `json:"encrypted_metadata_bytes"`
	OpaqueBytes            int64   `json:"opaque_bytes"`
	OpaquePercent          float64 `json:"opaque_percent"`
}

type ProtocolSummaryReader interface {
	QueryProtocolSummary(context.Context, ProtocolSummaryQuery) (ProtocolSummary, error)
}

// ParseInternalProtocolSummaryQuery parses the private ingestd query.
func ParseInternalProtocolSummaryQuery(values url.Values) (ProtocolSummaryQuery, error) {
	allowed := map[string]bool{"window_seconds": true, "device_id": true, "category": true, "exotic": true}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return ProtocolSummaryQuery{}, errors.New("protocol summary query contains an unsupported or repeated parameter")
		}
	}
	query := ProtocolSummaryQuery{WindowSeconds: protocolSummaryWindows[DefaultProtocolSummaryWindow], DeviceID: values.Get("device_id"), Category: values.Get("category")}
	if raw := values.Get("window_seconds"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil {
			return ProtocolSummaryQuery{}, errors.New("protocol summary window is invalid")
		}
		query.WindowSeconds = seconds
	}
	if raw := values.Get("exotic"); raw != "" {
		exotic, err := strconv.ParseBool(raw)
		if err != nil {
			return ProtocolSummaryQuery{}, errors.New("protocol summary exotic filter must be true or false")
		}
		query.Exotic = &exotic
	}
	if err := query.Validate(); err != nil {
		return ProtocolSummaryQuery{}, err
	}
	return query, nil
}

func encodeProtocolSummaryQuery(query ProtocolSummaryQuery) (url.Values, error) {
	if err := query.Validate(); err != nil {
		return nil, err
	}
	values := make(url.Values)
	values.Set("window_seconds", strconv.Itoa(query.WindowSeconds))
	if query.DeviceID != "" {
		values.Set("device_id", query.DeviceID)
	}
	if query.Category != "" {
		values.Set("category", query.Category)
	}
	if query.Exotic != nil {
		values.Set("exotic", strconv.FormatBool(*query.Exotic))
	}
	return values, nil
}

// Validate checks a protocol summary query.
func (query ProtocolSummaryQuery) Validate() error {
	if protocolSummaryWindowLabel(query.WindowSeconds) == "" {
		return errors.New("protocol summary window must be 1h, 24h, 7d, or 30d")
	}
	if query.DeviceID != "" && !deviceIDPattern.MatchString(query.DeviceID) {
		return errors.New("protocol summary device ID is invalid")
	}
	if query.Category != "" && !protocolclass.ValidCategory(query.Category) {
		return errors.New("protocol summary category is not a known category; list categories with GET /api/v1/protocols/catalog")
	}
	return nil
}

func (query ProtocolSummaryQuery) includes(protocol protocolclass.Protocol) bool {
	if query.Category != "" && string(protocol.Category) != query.Category {
		return false
	}
	return query.Exotic == nil || protocol.Exotic == *query.Exotic
}

// protocolSummaryStatement aggregates classified events in one statement.
//
// Dedupe rule. Flows are counted once, from one vantage point:
//   - Passive analysis: zeek.conn rows are the flows of a capture; a
//     capture's suricata.flow rows count only when that capture has no
//     zeek.conn rows in the window (Suricata-only analysis).
//   - Interception: a mitmproxy TLS outcome (intercepted, passthrough,
//     failed) is one connection. It counts as a flow only when no passive
//     flow has the same 5-tuple within ten minutes; otherwise it upgrades
//     that passive flow to DECRYPTED when ShakerProxy decrypted it.
//   - Everything else (dns.log, http.log, ssl.log, Suricata app-layer and
//     alert records, mitmproxy HTTP/DoH records) is protocol evidence: it
//     makes a protocol appear with events, devices, and first/last seen,
//     but never adds flows or bytes.
const protocolSummaryStatement = `WITH win AS MATERIALIZED (
SELECT source::text AS source, kind, capture_session_id, device_id, occurred_at, source_ip, source_port,
destination_ip, destination_port, COALESCE(protocol, '') AS transport, COALESCE(network_bytes, 0)::bigint AS bytes,
app_protocol, COALESCE(protocol_visibility, 'OPAQUE') AS visibility,
COALESCE(protocol_evidence, 'UNCLASSIFIED') AS evidence, tls_interception_state
FROM normalized_events
WHERE occurred_at >= $1 AND occurred_at <= $2 AND app_protocol IS NOT NULL %s
ORDER BY occurred_at DESC, record_id DESC
LIMIT %d
), zeek_captures AS MATERIALIZED (
SELECT DISTINCT capture_session_id FROM win WHERE kind = 'zeek.conn' AND capture_session_id IS NOT NULL
), passive AS MATERIALIZED (
SELECT * FROM win WHERE kind = 'zeek.conn'
UNION ALL
SELECT w.* FROM win w WHERE w.kind = 'suricata.flow'
AND NOT EXISTS (SELECT 1 FROM zeek_captures z WHERE z.capture_session_id = w.capture_session_id)
), intercepted AS MATERIALIZED (
SELECT * FROM win WHERE source = 'MITMPROXY' AND kind IN ('tls_intercepted', 'tls_passthrough', 'tls_interception_failed')
), flows AS MATERIALIZED (
SELECT p.app_protocol, p.device_id, p.occurred_at, p.transport, p.destination_port, p.bytes,
CASE WHEN p.visibility = 'ENCRYPTED_METADATA' AND EXISTS (
SELECT 1 FROM intercepted m WHERE m.tls_interception_state = 'INTERCEPTED'
AND m.source_ip = p.source_ip AND m.source_port = p.source_port
AND m.destination_ip = p.destination_ip AND m.destination_port = p.destination_port
AND m.occurred_at BETWEEN p.occurred_at - $3::interval AND p.occurred_at + $3::interval
) THEN 'DECRYPTED' ELSE p.visibility END AS visibility
FROM passive p
UNION ALL
SELECT m.app_protocol, m.device_id, m.occurred_at, m.transport, m.destination_port, m.bytes, m.visibility
FROM intercepted m
WHERE NOT EXISTS (
SELECT 1 FROM passive p WHERE p.source_ip = m.source_ip AND p.source_port = m.source_port
AND p.destination_ip = m.destination_ip AND p.destination_port = m.destination_port
AND p.occurred_at BETWEEN m.occurred_at - $3::interval AND m.occurred_at + $3::interval)
), device_rows AS (
SELECT app_protocol, device_id, sum(flow_count)::bigint AS flows, sum(bytes)::bigint AS bytes, max(seen) AS last_seen
FROM (
SELECT app_protocol, device_id, 1 AS flow_count, bytes, occurred_at AS seen FROM flows WHERE device_id IS NOT NULL
UNION ALL
SELECT app_protocol, device_id, 0, 0::bigint, occurred_at FROM win WHERE device_id IS NOT NULL
) contributions GROUP BY app_protocol, device_id
), ranked_devices AS (
SELECT app_protocol, device_id, flows, bytes, last_seen,
row_number() OVER (PARTITION BY app_protocol ORDER BY flows DESC, bytes DESC, last_seen DESC, device_id) AS rank
FROM device_rows
), ranked_ports AS (
SELECT app_protocol, transport, destination_port, flows,
row_number() OVER (PARTITION BY app_protocol ORDER BY flows DESC, destination_port, transport) AS rank
FROM (
SELECT app_protocol, transport, destination_port, count(*)::bigint AS flows FROM flows
WHERE destination_port IS NOT NULL AND transport <> '' GROUP BY app_protocol, transport, destination_port
) port_rows
)
SELECT 'flow'::text AS row_kind, app_protocol, ''::text AS device_id, ''::text AS label,
0 AS port, mode() WITHIN GROUP (ORDER BY visibility) AS visibility,
count(*)::bigint AS first_count, count(*) FILTER (WHERE device_id IS NULL)::bigint AS second_count,
COALESCE(sum(bytes), 0)::bigint AS bytes, min(occurred_at) AS first_at, max(occurred_at) AS last_at,
false AS first_flag, false AS second_flag, 0::bigint AS rank
FROM flows GROUP BY app_protocol
UNION ALL
SELECT 'event', app_protocol, '', '', 0, mode() WITHIN GROUP (ORDER BY visibility),
count(*)::bigint, count(DISTINCT device_id)::bigint, 0::bigint, min(occurred_at), max(occurred_at),
bool_or(evidence = 'ANALYZER'), bool_or(evidence = 'PORT_HEURISTIC'), 0::bigint
FROM win GROUP BY app_protocol
UNION ALL
SELECT 'device', app_protocol, device_id, '', 0, '', flows, 0::bigint, bytes, last_seen, last_seen, false, false, rank
FROM ranked_devices WHERE rank <= $4
UNION ALL
SELECT 'port', app_protocol, '', transport, destination_port, '', flows, 0::bigint, 0::bigint, NULL::timestamptz, NULL::timestamptz, false, false, rank
FROM ranked_ports WHERE rank <= $5
UNION ALL
SELECT 'coverage', '', '', '', 0, visibility, count(*)::bigint, 0::bigint, COALESCE(sum(bytes), 0)::bigint, NULL::timestamptz, NULL::timestamptz, false, false, 0::bigint
FROM flows GROUP BY visibility
UNION ALL
SELECT 'source', '', '', source, 0, '', count(*)::bigint, 0::bigint, 0::bigint, NULL::timestamptz, NULL::timestamptz, false, false, 0::bigint
FROM win GROUP BY source
UNION ALL
SELECT 'first_ever', p.app_protocol, '', '', 0, '', 0::bigint, 0::bigint, 0::bigint,
(SELECT min(n.occurred_at) FROM normalized_events n WHERE n.app_protocol = p.app_protocol), NULL::timestamptz, false, false, 0::bigint
FROM (SELECT DISTINCT app_protocol FROM win) p
UNION ALL
SELECT 'scanned', '', '', '', 0, '', (SELECT count(*) FROM win)::bigint, 0::bigint, 0::bigint, NULL::timestamptz, NULL::timestamptz, false, false, 0::bigint`

// QueryProtocolSummary aggregates protocol discovery for the window.
func (s PostgresSink) QueryProtocolSummary(ctx context.Context, query ProtocolSummaryQuery) (ProtocolSummary, error) {
	if s.DB == nil {
		return ProtocolSummary{}, errors.New("PostgreSQL connection is required")
	}
	if err := query.Validate(); err != nil {
		return ProtocolSummary{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return ProtocolSummary{}, fmt.Errorf("begin protocol summary query: %w", err)
	}
	defer tx.Rollback()
	var generatedAt time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&generatedAt); err != nil {
		return ProtocolSummary{}, fmt.Errorf("read protocol summary boundary: %w", err)
	}
	generatedAt = generatedAt.UTC()
	windowStart := generatedAt.Add(-time.Duration(query.WindowSeconds) * time.Second)
	args := []any{windowStart, generatedAt, fmt.Sprintf("%d seconds", int(protocolSummaryCorrelationSkew/time.Second)), MaxSummaryDevicesPerProtocol + 1, MaxSummaryPortsPerProtocol + 1}
	deviceClause := ""
	if query.DeviceID != "" {
		args = append(args, query.DeviceID)
		deviceClause = fmt.Sprintf("AND device_id = $%d", len(args))
	}
	statement := fmt.Sprintf(protocolSummaryStatement, deviceClause, MaxProtocolSummaryScannedRows+1)
	rows, err := tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return ProtocolSummary{}, fmt.Errorf("query protocol summary: %w", err)
	}
	defer rows.Close()
	builder := newProtocolSummaryBuilder(query, generatedAt, windowStart)
	for rows.Next() {
		var row protocolSummaryRow
		var firstAt, lastAt sql.NullTime
		if err := rows.Scan(&row.kind, &row.protocol, &row.deviceID, &row.label, &row.port, &row.visibility, &row.firstCount, &row.secondCount, &row.bytes, &firstAt, &lastAt, &row.firstFlag, &row.secondFlag, &row.rank); err != nil {
			return ProtocolSummary{}, fmt.Errorf("decode protocol summary: %w", err)
		}
		row.firstAt, row.lastAt = firstAt.Time.UTC(), lastAt.Time.UTC()
		builder.add(row)
	}
	if err := rows.Err(); err != nil {
		return ProtocolSummary{}, fmt.Errorf("read protocol summary: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ProtocolSummary{}, fmt.Errorf("commit protocol summary query: %w", err)
	}
	summary := builder.build()
	if err := summary.Validate(query); err != nil {
		return ProtocolSummary{}, err
	}
	return summary, nil
}

type protocolSummaryRow struct {
	kind, protocol, deviceID, label, visibility string
	port                                        int
	firstCount, secondCount, bytes, rank        int64
	firstAt, lastAt                             time.Time
	firstFlag, secondFlag                       bool
}

type protocolAccumulator struct {
	usage          ProtocolUsage
	flowVisibility string
	evidenceSeen   bool
	analyzer, port bool
	firstEver      time.Time
}

type protocolSummaryBuilder struct {
	query       ProtocolSummaryQuery
	summary     ProtocolSummary
	protocols   map[string]*protocolAccumulator
	coverage    map[string]int64
	sources     map[Source]bool
	truncated   bool
	scannedRows int64
}

func newProtocolSummaryBuilder(query ProtocolSummaryQuery, generatedAt, windowStart time.Time) *protocolSummaryBuilder {
	return &protocolSummaryBuilder{
		query: query,
		summary: ProtocolSummary{
			Schema: ProtocolSummarySchemaVersion, GeneratedAt: generatedAt, Window: protocolSummaryWindowLabel(query.WindowSeconds),
			WindowStart: windowStart, WindowEnd: generatedAt, DeviceID: query.DeviceID,
		},
		protocols: map[string]*protocolAccumulator{},
		coverage:  map[string]int64{},
		sources:   map[Source]bool{},
	}
}

func (b *protocolSummaryBuilder) protocol(id string) *protocolAccumulator {
	accumulator := b.protocols[id]
	if accumulator == nil {
		accumulator = &protocolAccumulator{usage: ProtocolUsage{Protocol: id, Devices: []ProtocolDeviceUsage{}, Ports: []ProtocolPortUsage{}}}
		b.protocols[id] = accumulator
	}
	return accumulator
}

func (b *protocolSummaryBuilder) add(row protocolSummaryRow) {
	switch row.kind {
	case "flow":
		accumulator := b.protocol(row.protocol)
		accumulator.usage.Flows, accumulator.usage.UnattributedFlows, accumulator.usage.Bytes = row.firstCount, row.secondCount, row.bytes
		accumulator.flowVisibility = row.visibility
	case "event":
		accumulator := b.protocol(row.protocol)
		accumulator.evidenceSeen = true
		accumulator.usage.Events, accumulator.usage.DeviceCount = row.firstCount, int(row.secondCount)
		accumulator.usage.FirstSeen, accumulator.usage.LastSeen = row.firstAt, row.lastAt
		accumulator.analyzer, accumulator.port = row.firstFlag, row.secondFlag
		accumulator.usage.Visibility = row.visibility
	case "device":
		accumulator := b.protocol(row.protocol)
		if row.rank > MaxSummaryDevicesPerProtocol {
			b.truncated = true
			return
		}
		accumulator.usage.Devices = append(accumulator.usage.Devices, ProtocolDeviceUsage{DeviceID: row.deviceID, Flows: row.firstCount, Bytes: row.bytes, LastSeen: row.lastAt})
	case "port":
		accumulator := b.protocol(row.protocol)
		if row.rank > MaxSummaryPortsPerProtocol {
			b.truncated = true
			return
		}
		accumulator.usage.Ports = append(accumulator.usage.Ports, ProtocolPortUsage{Transport: row.label, Port: row.port, Flows: row.firstCount})
	case "coverage":
		b.coverage[row.visibility] += row.bytes
	case "source":
		b.sources[Source(row.label)] = true
	case "first_ever":
		b.protocol(row.protocol).firstEver = row.firstAt
	case "scanned":
		b.scannedRows = row.firstCount
	}
}

func (b *protocolSummaryBuilder) build() ProtocolSummary {
	summary := b.summary
	summary.Protocols = make([]ProtocolUsage, 0, len(b.protocols))
	for id, accumulator := range b.protocols {
		protocol, known := protocolclass.Lookup(id)
		if !known || !accumulator.evidenceSeen || !b.query.includes(protocol) {
			continue
		}
		usage := accumulator.usage
		usage.Label, usage.Category, usage.Exotic, usage.Description = protocol.Label, string(protocol.Category), protocol.Exotic, protocol.Description
		if accumulator.flowVisibility != "" {
			usage.Visibility = accumulator.flowVisibility
		}
		if !protocolclass.ValidVisibility(usage.Visibility) {
			usage.Visibility = string(protocol.Visibility)
		}
		switch {
		case accumulator.analyzer:
			usage.Evidence = string(protocolclass.EvidenceAnalyzer)
		case accumulator.port:
			usage.Evidence = string(protocolclass.EvidencePort)
		default:
			usage.Evidence = string(protocolclass.EvidenceUnclassified)
		}
		usage.Novel = !accumulator.firstEver.IsZero() && !accumulator.firstEver.Before(summary.WindowStart)
		sort.SliceStable(usage.Ports, func(i, j int) bool {
			if usage.Ports[i].Flows != usage.Ports[j].Flows {
				return usage.Ports[i].Flows > usage.Ports[j].Flows
			}
			return usage.Ports[i].Port < usage.Ports[j].Port
		})
		sort.SliceStable(usage.Devices, func(i, j int) bool {
			if usage.Devices[i].Flows != usage.Devices[j].Flows {
				return usage.Devices[i].Flows > usage.Devices[j].Flows
			}
			if usage.Devices[i].Bytes != usage.Devices[j].Bytes {
				return usage.Devices[i].Bytes > usage.Devices[j].Bytes
			}
			return usage.Devices[i].DeviceID < usage.Devices[j].DeviceID
		})
		summary.Protocols = append(summary.Protocols, usage)
	}
	sort.Slice(summary.Protocols, func(i, j int) bool {
		left, right := summary.Protocols[i], summary.Protocols[j]
		if left.Bytes != right.Bytes {
			return left.Bytes > right.Bytes
		}
		if left.Flows != right.Flows {
			return left.Flows > right.Flows
		}
		if left.Events != right.Events {
			return left.Events > right.Events
		}
		return left.Protocol < right.Protocol
	})
	if len(summary.Protocols) > MaxSummaryProtocols {
		summary.Protocols = summary.Protocols[:MaxSummaryProtocols]
		b.truncated = true
	}
	coverage := ProtocolCoverage{
		DecryptedBytes:         b.coverage[string(protocolclass.VisibilityDecrypted)],
		CleartextBytes:         b.coverage[string(protocolclass.VisibilityCleartext)],
		EncryptedMetadataBytes: b.coverage[string(protocolclass.VisibilityEncryptedMetadata)],
		OpaqueBytes:            b.coverage[string(protocolclass.VisibilityOpaque)],
	}
	coverage.TotalBytes = coverage.DecryptedBytes + coverage.CleartextBytes + coverage.EncryptedMetadataBytes + coverage.OpaqueBytes
	if coverage.TotalBytes > 0 {
		coverage.OpaquePercent = math.Round(float64(coverage.OpaqueBytes)*1000/float64(coverage.TotalBytes)) / 10
	}
	summary.Coverage = coverage
	summary.Sources = make([]Source, 0, len(b.sources))
	for _, source := range []Source{SourceZeek, SourceSuricata, SourceMitmproxy, SourceHost} {
		if b.sources[source] {
			summary.Sources = append(summary.Sources, source)
		}
	}
	summary.Truncated = b.truncated || b.scannedRows > MaxProtocolSummaryScannedRows
	return summary
}

// Validate checks a protocol summary against its query and bounds. Clients
// use it to refuse malformed or out-of-scope storage responses.
func (summary ProtocolSummary) Validate(query ProtocolSummaryQuery) error {
	if err := query.Validate(); err != nil {
		return err
	}
	if summary.Schema != ProtocolSummarySchemaVersion || summary.GeneratedAt.IsZero() || summary.Window != protocolSummaryWindowLabel(query.WindowSeconds) || !summary.WindowEnd.Equal(summary.GeneratedAt) || !summary.WindowStart.Equal(summary.WindowEnd.Add(-time.Duration(query.WindowSeconds)*time.Second)) || summary.DeviceID != query.DeviceID {
		return errors.New("protocol summary boundary is invalid")
	}
	if summary.Protocols == nil || len(summary.Protocols) > MaxSummaryProtocols || summary.Sources == nil || len(summary.Sources) > 4 {
		return errors.New("protocol summary exceeds its bounds")
	}
	coverage := summary.Coverage
	if coverage.DecryptedBytes < 0 || coverage.CleartextBytes < 0 || coverage.EncryptedMetadataBytes < 0 || coverage.OpaqueBytes < 0 || coverage.TotalBytes != coverage.DecryptedBytes+coverage.CleartextBytes+coverage.EncryptedMetadataBytes+coverage.OpaqueBytes || coverage.OpaquePercent < 0 || coverage.OpaquePercent > 100 {
		return errors.New("protocol summary coverage is inconsistent")
	}
	seen := make(map[string]bool, len(summary.Protocols))
	for _, usage := range summary.Protocols {
		protocol, known := protocolclass.Lookup(usage.Protocol)
		if !known || seen[usage.Protocol] || !query.includes(protocol) || usage.Label != protocol.Label || usage.Category != string(protocol.Category) || usage.Exotic != protocol.Exotic || usage.Description != protocol.Description || !protocolclass.ValidVisibility(usage.Visibility) {
			return errors.New("protocol summary contains an unknown or out-of-scope protocol")
		}
		seen[usage.Protocol] = true
		switch protocolclass.Evidence(usage.Evidence) {
		case protocolclass.EvidenceAnalyzer, protocolclass.EvidencePort, protocolclass.EvidenceUnclassified:
		default:
			return errors.New("protocol summary evidence is invalid")
		}
		if usage.Flows < 0 || usage.Bytes < 0 || usage.Events < 1 || usage.Flows > usage.Events || usage.UnattributedFlows < 0 || usage.UnattributedFlows > usage.Flows || usage.DeviceCount < len(usage.Devices) || usage.FirstSeen.IsZero() || usage.LastSeen.Before(usage.FirstSeen) || usage.FirstSeen.Before(summary.WindowStart) || usage.LastSeen.After(summary.WindowEnd) {
			return errors.New("protocol summary counts are inconsistent")
		}
		if usage.Devices == nil || usage.Ports == nil || len(usage.Devices) > MaxSummaryDevicesPerProtocol || len(usage.Ports) > MaxSummaryPortsPerProtocol {
			return errors.New("protocol summary exceeds its per-protocol bounds")
		}
		for _, device := range usage.Devices {
			if !deviceIDPattern.MatchString(device.DeviceID) || query.DeviceID != "" && device.DeviceID != query.DeviceID || device.Flows < 0 || device.Bytes < 0 || device.LastSeen.IsZero() || len(device.DeviceName) > 256 {
				return errors.New("protocol summary contains an invalid device")
			}
		}
		for _, port := range usage.Ports {
			if port.Port < 1 || port.Port > 65535 || port.Flows < 1 || !projectionTextPattern.MatchString(port.Transport) {
				return errors.New("protocol summary contains an invalid port")
			}
		}
	}
	for _, source := range summary.Sources {
		switch source {
		case SourceZeek, SourceSuricata, SourceMitmproxy, SourceHost:
		default:
			return errors.New("protocol summary contains an invalid source")
		}
	}
	return nil
}

// ProtocolCatalog is the public protocol catalog response.
type ProtocolCatalog struct {
	Schema     int                      `json:"schema"`
	Categories []string                 `json:"categories"`
	Protocols  []protocolclass.Protocol `json:"protocols"`
}

// NewProtocolCatalog returns the catalog in display order.
func NewProtocolCatalog() ProtocolCatalog {
	categories := protocolclass.Categories()
	names := make([]string, 0, len(categories))
	for _, category := range categories {
		names = append(names, string(category))
	}
	return ProtocolCatalog{Schema: ProtocolSummarySchemaVersion, Categories: names, Protocols: protocolclass.Catalog()}
}
