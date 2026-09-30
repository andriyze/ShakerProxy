package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Device activity is a read-only, bounded aggregation of one device's
// normalized events over one time range. It powers device reports, findings,
// and run comparison. It reads only existing projected columns and a few
// bounded scalar payload fields (host names, TLS versions, HTTP status codes,
// and IDS signature names); it never returns payload bodies, headers, paths,
// or query strings.
const (
	MaxDeviceActivityWindow      = 31 * 24 * time.Hour
	MaxDeviceActivityDomainRows  = 1500
	MaxDeviceActivityFlowGroups  = 1000
	MaxDeviceActivityTLSHosts    = 500
	MaxDeviceActivityTLSVersions = 200
	MaxDeviceActivityHTTPHosts   = 200
	MaxDeviceActivityAlerts      = 100
	MaxDeviceActivityResolvers   = 100
	maxDeviceActivityTextBytes   = 256
)

// Domain observation sources.
const (
	DeviceDomainSourceDNS  = "dns"
	DeviceDomainSourceTLS  = "tls"
	DeviceDomainSourceHTTP = "http"
)

// PinningFailureReasons are the exact interception failure reasons that
// indicate probable certificate pinning or a custom trust store. The generic
// "ca_not_trusted_or_pinning" reason is deliberately excluded: it usually means
// the ShakerProxy CA is simply not installed.
var PinningFailureReasons = []string{
	"probable_certificate_pinning_or_custom_trust_store",
	"dynamic_probable_pinning_bypass",
}

var (
	activityHostPattern     = regexp.MustCompile(`^[a-z0-9_*-]+(\.[a-z0-9_*-]+)*$`)
	activityTransportValues = map[string]struct{}{"": {}, "tcp": {}, "udp": {}, "icmp": {}, "icmpv6": {}, "ipv6-icmp": {}, "sctp": {}}
)

type DeviceActivityQuery struct {
	DeviceID string
	Start    time.Time
	End      time.Time
	// Addresses are the device's addresses during the window. Connections
	// that other hosts opened to them are reported as inbound flow groups,
	// even when the event was attributed to the connecting device.
	Addresses []string
}

// MaxDeviceActivityAddresses bounds the addresses one query may match.
const MaxDeviceActivityAddresses = 16

type DeviceActivity struct {
	Schema        int                       `json:"schema"`
	GeneratedAt   time.Time                 `json:"generated_at"`
	DeviceID      string                    `json:"device_id"`
	Start         time.Time                 `json:"start"`
	End           time.Time                 `json:"end"`
	Counts        DeviceActivityCounts      `json:"counts"`
	Domains       []DeviceDomainObservation `json:"domains"`
	FlowGroups    []DeviceFlowGroup         `json:"flow_groups"`
	TLSHosts      []DeviceTLSHost           `json:"tls_hosts"`
	TLSVersions   []DeviceTLSVersion        `json:"tls_versions"`
	CleartextHTTP []DeviceHTTPHost          `json:"cleartext_http"`
	HTTPStatus    []DeviceHTTPStatusCount   `json:"http_status"`
	Alerts        []DeviceAlertGroup        `json:"alerts"`
	EncryptedDNS  []DeviceResolver          `json:"encrypted_dns"`
	Truncated     bool                      `json:"truncated"`
}

// DeviceActivityCounts keeps per-sensor counts separate so callers can avoid
// double counting when Zeek, Suricata, and the interceptor observe the same
// connection.
type DeviceActivityCounts struct {
	Events                       int64 `json:"events"`
	ZeekConnections              int64 `json:"zeek_connections"`
	ZeekConnectionBytes          int64 `json:"zeek_connection_bytes"`
	SuricataFlows                int64 `json:"suricata_flows"`
	SuricataFlowBytes            int64 `json:"suricata_flow_bytes"`
	ZeekDNS                      int64 `json:"zeek_dns"`
	SuricataDNS                  int64 `json:"suricata_dns"`
	ZeekTLS                      int64 `json:"zeek_tls"`
	SuricataTLS                  int64 `json:"suricata_tls"`
	InterceptorTLS               int64 `json:"interceptor_tls"`
	TLSIntercepted               int64 `json:"tls_intercepted"`
	TLSBypassed                  int64 `json:"tls_bypassed"`
	TLSFailed                    int64 `json:"tls_failed"`
	TLSPinningSuspected          int64 `json:"tls_pinning_suspected"`
	InterceptorHTTPRequests      int64 `json:"interceptor_http_requests"`
	InterceptorCleartextRequests int64 `json:"interceptor_cleartext_requests"`
	ZeekHTTP                     int64 `json:"zeek_http"`
	SuricataHTTP                 int64 `json:"suricata_http"`
	Alerts                       int64 `json:"alerts"`
	EncryptedDNSDetections       int64 `json:"encrypted_dns_detections"`
}

type DeviceDomainObservation struct {
	Domain    string    `json:"domain"`
	Source    string    `json:"source"`
	Events    int64     `json:"events"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// DeviceFlowGroup aggregates connection records that share a sensor,
// transport, analyzer service, server port, privileged client port, and
// direction. Inbound means the device was the responder.
type DeviceFlowGroup struct {
	Source      Source    `json:"source"`
	Transport   string    `json:"transport"`
	Service     string    `json:"service"`
	ServerPort  int       `json:"server_port"`
	ClientPort  int       `json:"client_port"`
	Inbound     bool      `json:"inbound"`
	Flows       int64     `json:"flows"`
	Bytes       int64     `json:"bytes"`
	Peers       int64     `json:"peers"`
	SamplePeer  string    `json:"sample_peer,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Intercepted bool      `json:"intercepted"`
}

type DeviceTLSHost struct {
	Host             string    `json:"host"`
	State            string    `json:"state"`
	FailureReason    string    `json:"failure_reason,omitempty"`
	PinningSuspected bool      `json:"pinning_suspected"`
	Events           int64     `json:"events"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

// DeviceTLSVersion reports a legacy (SSL, TLS 1.0, or TLS 1.1) handshake
// version seen by Zeek or Suricata for one server name.
type DeviceTLSVersion struct {
	Version   string    `json:"version"`
	Host      string    `json:"host"`
	Events    int64     `json:"events"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type DeviceHTTPHost struct {
	Host          string    `json:"host"`
	Requests      int64     `json:"requests"`
	SampleAddress string    `json:"sample_address,omitempty"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// DeviceHTTPStatusCount counts responses per sensor and status class.
// Cleartext marks unencrypted HTTP, which Zeek, Suricata, and the interceptor
// may all observe; decrypted HTTPS is seen only by the interceptor.
type DeviceHTTPStatusCount struct {
	Source    Source `json:"source"`
	Cleartext bool   `json:"cleartext"`
	Class     string `json:"class"`
	Count     int64  `json:"count"`
}

type DeviceAlertGroup struct {
	Engine    string    `json:"engine"`
	Signature string    `json:"signature"`
	Severity  string    `json:"severity"`
	Category  string    `json:"category,omitempty"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type DeviceResolver struct {
	Host      string    `json:"host"`
	Transport string    `json:"transport"`
	Events    int64     `json:"events"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type DeviceActivityReader interface {
	QueryDeviceActivity(context.Context, DeviceActivityQuery) (DeviceActivity, error)
}

func ParseInternalDeviceActivityQuery(values url.Values) (DeviceActivityQuery, error) {
	allowed := map[string]bool{"device_id": true, "start": true, "end": true}
	for key, entries := range values {
		if key == "address" && len(entries) <= MaxDeviceActivityAddresses {
			continue
		}
		if !allowed[key] || len(entries) != 1 {
			return DeviceActivityQuery{}, errors.New("device activity query contains an unsupported or repeated parameter")
		}
	}
	start, err := time.Parse(time.RFC3339Nano, values.Get("start"))
	if err != nil {
		return DeviceActivityQuery{}, errors.New("device activity start must be an RFC 3339 timestamp")
	}
	end, err := time.Parse(time.RFC3339Nano, values.Get("end"))
	if err != nil {
		return DeviceActivityQuery{}, errors.New("device activity end must be an RFC 3339 timestamp")
	}
	query := DeviceActivityQuery{DeviceID: strings.TrimSpace(values.Get("device_id")), Start: start.UTC(), End: end.UTC(), Addresses: values["address"]}
	if err := validateDeviceActivityQuery(query); err != nil {
		return DeviceActivityQuery{}, err
	}
	return query, nil
}

func encodeDeviceActivityQuery(query DeviceActivityQuery) (url.Values, error) {
	if err := validateDeviceActivityQuery(query); err != nil {
		return nil, err
	}
	values := make(url.Values)
	values.Set("device_id", query.DeviceID)
	values.Set("start", query.Start.UTC().Format(time.RFC3339Nano))
	values.Set("end", query.End.UTC().Format(time.RFC3339Nano))
	for _, address := range query.Addresses {
		values.Add("address", address)
	}
	return values, nil
}

func validateDeviceActivityQuery(query DeviceActivityQuery) error {
	if !deviceIDPattern.MatchString(query.DeviceID) {
		return errors.New("device activity device ID is invalid")
	}
	if query.Start.Year() < 2000 || query.End.Year() > 3000 || !query.End.After(query.Start) {
		return errors.New("device activity time range is invalid")
	}
	if !query.Start.Truncate(time.Microsecond).Equal(query.Start) || !query.End.Truncate(time.Microsecond).Equal(query.End) {
		return errors.New("device activity time range must use microsecond precision")
	}
	if query.End.Sub(query.Start) > MaxDeviceActivityWindow {
		return errors.New("device activity time range exceeds 31 days")
	}
	if len(query.Addresses) > MaxDeviceActivityAddresses {
		return errors.New("device activity query has too many addresses")
	}
	for _, raw := range query.Addresses {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.Zone() != "" || address.Unmap().String() != raw {
			return errors.New("device activity addresses must be canonical IP addresses")
		}
	}
	return nil
}

const deviceActivityScope = "device_id = $1 AND occurred_at >= $2 AND occurred_at < $3"

const deviceActivityPinningReasons = "('probable_certificate_pinning_or_custom_trust_store','dynamic_probable_pinning_bypass')"

const deviceActivityCountsStatement = `SELECT
count(*),
count(*) FILTER (WHERE kind = 'zeek.conn'),
COALESCE(sum(network_bytes) FILTER (WHERE kind = 'zeek.conn'), 0),
count(*) FILTER (WHERE kind = 'suricata.flow'),
COALESCE(sum(network_bytes) FILTER (WHERE kind = 'suricata.flow'), 0),
count(*) FILTER (WHERE kind = 'zeek.dns' AND dns_query IS NOT NULL),
count(*) FILTER (WHERE kind = 'suricata.dns' AND dns_query IS NOT NULL AND COALESCE(payload->'dns'->>'type', '') NOT IN ('answer', 'response')),
count(*) FILTER (WHERE kind = 'zeek.ssl'),
count(*) FILTER (WHERE kind = 'suricata.tls'),
count(*) FILTER (WHERE source = 'MITMPROXY' AND tls_interception_state IS NOT NULL),
count(*) FILTER (WHERE tls_interception_state = 'INTERCEPTED'),
count(*) FILTER (WHERE tls_interception_state = 'BYPASSED'),
count(*) FILTER (WHERE tls_interception_state = 'FAILED'),
count(*) FILTER (WHERE tls_interception_state IS NOT NULL AND (COALESCE(tls_pinning_suspected, FALSE) OR tls_failure_reason IN ` + deviceActivityPinningReasons + `)),
count(DISTINCT COALESCE(flow_id, record_id)) FILTER (WHERE source = 'MITMPROXY' AND kind IN ('http_request', 'http_response')),
count(DISTINCT COALESCE(flow_id, record_id)) FILTER (WHERE source = 'MITMPROXY' AND kind IN ('http_request', 'http_response') AND lower(COALESCE(payload->>'http_scheme', '')) = 'http'),
count(*) FILTER (WHERE kind = 'zeek.http'),
count(*) FILTER (WHERE kind = 'suricata.http'),
count(*) FILTER (WHERE kind = 'suricata.alert' OR kind LIKE 'shakerproxy.detection.%'),
count(*) FILTER (WHERE source = 'MITMPROXY' AND (kind = 'encrypted_dns_detected' OR service = 'doh'))
FROM normalized_events WHERE ` + deviceActivityScope

const deviceActivityDomainsStatement = `SELECT domain, origin, count(*), min(occurred_at), max(occurred_at) FROM (
SELECT lower(rtrim(dns_query, '.')) AS domain, 'dns' AS origin, occurred_at FROM normalized_events
 WHERE ` + deviceActivityScope + ` AND dns_query IS NOT NULL AND (kind = 'zeek.dns' OR (kind = 'suricata.dns' AND COALESCE(payload->'dns'->>'type', '') NOT IN ('answer', 'response')))
UNION ALL
SELECT lower(rtrim(COALESCE(tls_server_name, NULLIF(payload->>'server_name', ''), NULLIF(payload->'tls'->>'sni', '')), '.')), 'tls', occurred_at FROM normalized_events
 WHERE ` + deviceActivityScope + ` AND (tls_server_name IS NOT NULL OR kind IN ('zeek.ssl', 'suricata.tls'))
UNION ALL
SELECT lower(rtrim(COALESCE(NULLIF(payload->>'http_host', ''), NULLIF(payload->>'host', ''), NULLIF(payload->'http'->>'hostname', '')), '.')), 'http', occurred_at FROM normalized_events
 WHERE ` + deviceActivityScope + ` AND ((source = 'MITMPROXY' AND kind IN ('http_request', 'http_response')) OR kind IN ('zeek.http', 'suricata.http'))
) observed WHERE domain IS NOT NULL AND domain <> '' AND length(domain) <= 260
GROUP BY domain, origin ORDER BY count(*) DESC, domain, origin LIMIT $4`

// deviceActivityFlowsStatement groups the device's connections. Besides the
// events attributed to the device, it counts connections other hosts opened
// to the device's addresses ($5) as inbound, so services the device accepts
// (for example Telnet opened from a laptop) appear on the device itself.
const deviceActivityFlowsStatement = `WITH flows AS (
SELECT source, protocol, service, destination_port, source_port, network_bytes, occurred_at, tls_interception_state, source_ip, destination_ip,
(COALESCE(attribution_evidence->>'endpoint', '') = 'DESTINATION' OR device_id IS DISTINCT FROM $1) AS inbound
FROM normalized_events
WHERE (` + deviceActivityScope + ` AND (kind IN ('zeek.conn', 'suricata.flow') OR (source = 'MITMPROXY' AND (tls_interception_state IS NOT NULL OR kind = 'encrypted_dns_detected'))))
OR (cardinality($5::text[]) > 0 AND occurred_at >= $2 AND occurred_at < $3 AND device_id IS DISTINCT FROM $1
    AND kind IN ('zeek.conn', 'suricata.flow') AND host(destination_ip) = ANY($5::text[]))
)
SELECT source, COALESCE(protocol, ''), COALESCE(service, ''), COALESCE(destination_port, 0),
CASE WHEN source_port < 1024 THEN source_port ELSE 0 END,
inbound,
count(*), COALESCE(sum(network_bytes), 0),
count(DISTINCT CASE WHEN inbound THEN source_ip ELSE destination_ip END),
COALESCE(min(host(CASE WHEN inbound THEN source_ip ELSE destination_ip END)), ''),
min(occurred_at), max(occurred_at),
bool_or(COALESCE(tls_interception_state, '') = 'INTERCEPTED')
FROM flows
GROUP BY 1, 2, 3, 4, 5, 6 ORDER BY count(*) DESC, 1, 2, 3, 4, 5, 6 LIMIT $4`

const deviceActivityTLSHostsStatement = `SELECT lower(COALESCE(tls_server_name, host(destination_ip), '')), tls_interception_state, COALESCE(tls_failure_reason, ''),
bool_or(COALESCE(tls_pinning_suspected, FALSE) OR COALESCE(tls_failure_reason, '') IN ` + deviceActivityPinningReasons + `),
count(*), min(occurred_at), max(occurred_at)
FROM normalized_events WHERE ` + deviceActivityScope + ` AND source = 'MITMPROXY' AND tls_interception_state IS NOT NULL
GROUP BY 1, 2, 3 ORDER BY count(*) DESC, 1, 2, 3 LIMIT $4`

const deviceActivityTLSVersionsStatement = `SELECT version, host, count(*), min(occurred_at), max(occurred_at) FROM (
SELECT upper(replace(replace(COALESCE(NULLIF(payload->>'version', ''), payload->'tls'->>'version', ''), ' ', ''), '.', '')) AS version,
lower(rtrim(COALESCE(NULLIF(payload->>'server_name', ''), NULLIF(payload->'tls'->>'sni', ''), host(destination_ip), ''), '.')) AS host, occurred_at
FROM normalized_events WHERE ` + deviceActivityScope + ` AND kind IN ('zeek.ssl', 'suricata.tls')
) versions WHERE version IN ('SSLV2', 'SSLV3', 'TLSV1', 'TLSV10', 'TLSV11', 'TLS10', 'TLS11', 'DTLSV10', 'DTLS10')
GROUP BY version, host ORDER BY count(*) DESC, version, host LIMIT $4`

const deviceActivityCleartextHTTPStatement = `SELECT host,
GREATEST(count(DISTINCT COALESCE(flow_id, record_id)) FILTER (WHERE source = 'MITMPROXY'), count(*) FILTER (WHERE source = 'ZEEK'), count(*) FILTER (WHERE source = 'SURICATA')),
COALESCE(min(address), ''), min(occurred_at), max(occurred_at) FROM (
SELECT lower(rtrim(COALESCE(NULLIF(payload->>'http_host', ''), NULLIF(payload->>'host', ''), NULLIF(payload->'http'->>'hostname', ''), host(destination_ip), ''), '.')) AS host,
host(destination_ip) AS address, source, flow_id, record_id, occurred_at
FROM normalized_events WHERE ` + deviceActivityScope + ` AND ((source = 'MITMPROXY' AND kind IN ('http_request', 'http_response') AND lower(COALESCE(payload->>'http_scheme', '')) = 'http') OR kind IN ('zeek.http', 'suricata.http'))
) cleartext WHERE host <> '' AND length(host) <= 260
GROUP BY host ORDER BY 2 DESC, host LIMIT $4`

const deviceActivityHTTPStatusStatement = `SELECT source, cleartext, class, count(*) FROM (
SELECT source, cleartext, CASE WHEN status ~ '^[1-5][0-9][0-9]$' THEN substr(status, 1, 1) || 'xx' END AS class FROM (
SELECT source, (source <> 'MITMPROXY' OR lower(COALESCE(payload->>'http_scheme', '')) = 'http') AS cleartext,
COALESCE(NULLIF(payload->>'http_status', ''), NULLIF(payload->>'status_code', ''), payload->'http'->>'status', '') AS status
FROM normalized_events WHERE ` + deviceActivityScope + ` AND ((source = 'MITMPROXY' AND kind = 'http_response') OR kind IN ('zeek.http', 'suricata.http'))
) statuses) classes WHERE class IS NOT NULL GROUP BY source, cleartext, class ORDER BY source, cleartext, class`

const deviceActivityAlertsStatement = `SELECT engine, signature, severity, category, count(*), min(occurred_at), max(occurred_at) FROM (
SELECT 'SURICATA' AS engine, COALESCE(payload->'alert'->>'signature', '') AS signature, COALESCE(payload->'alert'->>'severity', '') AS severity,
COALESCE(payload->'alert'->>'category', '') AS category, occurred_at
FROM normalized_events WHERE ` + deviceActivityScope + ` AND kind = 'suricata.alert'
UNION ALL
SELECT 'SHAKERPROXY', COALESCE(detection_summary, detection_type, kind), COALESCE(detection_severity, 'WARNING'), COALESCE(detection_type, ''), occurred_at
FROM normalized_events WHERE ` + deviceActivityScope + ` AND kind LIKE 'shakerproxy.detection.%'
) alerts WHERE signature <> '' GROUP BY 1, 2, 3, 4 ORDER BY count(*) DESC, 1, 2, 3, 4 LIMIT $4`

const deviceActivityResolversStatement = `SELECT lower(rtrim(COALESCE(NULLIF(payload->>'hostname', ''), tls_server_name, host(destination_ip), ''), '.')),
upper(COALESCE(NULLIF(payload->>'dns_transport', ''), 'DOH')), count(*), min(occurred_at), max(occurred_at)
FROM normalized_events WHERE ` + deviceActivityScope + ` AND source = 'MITMPROXY' AND (kind = 'encrypted_dns_detected' OR service = 'doh')
GROUP BY 1, 2 ORDER BY count(*) DESC, 1, 2 LIMIT $4`

// QueryDeviceActivity runs every aggregation inside one read-only repeatable
// read transaction, so all sections describe the same snapshot without
// blocking ingestion.
func (s PostgresSink) QueryDeviceActivity(ctx context.Context, query DeviceActivityQuery) (DeviceActivity, error) {
	if s.DB == nil {
		return DeviceActivity{}, errors.New("PostgreSQL connection is required")
	}
	if err := validateDeviceActivityQuery(query); err != nil {
		return DeviceActivity{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return DeviceActivity{}, fmt.Errorf("begin device activity query: %w", err)
	}
	defer tx.Rollback()
	var generatedAt time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&generatedAt); err != nil {
		return DeviceActivity{}, fmt.Errorf("read device activity boundary: %w", err)
	}
	activity := DeviceActivity{
		Schema: SchemaVersion, GeneratedAt: generatedAt.UTC(), DeviceID: query.DeviceID,
		Start: query.Start.UTC(), End: query.End.UTC(),
		Domains: []DeviceDomainObservation{}, FlowGroups: []DeviceFlowGroup{}, TLSHosts: []DeviceTLSHost{},
		TLSVersions: []DeviceTLSVersion{}, CleartextHTTP: []DeviceHTTPHost{}, HTTPStatus: []DeviceHTTPStatusCount{},
		Alerts: []DeviceAlertGroup{}, EncryptedDNS: []DeviceResolver{},
	}
	scope := []any{query.DeviceID, activity.Start, activity.End}
	counts := &activity.Counts
	if err := tx.QueryRowContext(ctx, deviceActivityCountsStatement, scope...).Scan(
		&counts.Events, &counts.ZeekConnections, &counts.ZeekConnectionBytes, &counts.SuricataFlows, &counts.SuricataFlowBytes,
		&counts.ZeekDNS, &counts.SuricataDNS, &counts.ZeekTLS, &counts.SuricataTLS, &counts.InterceptorTLS,
		&counts.TLSIntercepted, &counts.TLSBypassed, &counts.TLSFailed, &counts.TLSPinningSuspected,
		&counts.InterceptorHTTPRequests, &counts.InterceptorCleartextRequests, &counts.ZeekHTTP, &counts.SuricataHTTP,
		&counts.Alerts, &counts.EncryptedDNSDetections,
	); err != nil {
		return DeviceActivity{}, fmt.Errorf("count device activity: %w", err)
	}
	if counts.Events > 0 || len(query.Addresses) > 0 {
		if err := readDeviceActivitySections(ctx, tx, scope, query.Addresses, &activity); err != nil {
			return DeviceActivity{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return DeviceActivity{}, fmt.Errorf("commit device activity query: %w", err)
	}
	if err := activity.Validate(query); err != nil {
		return DeviceActivity{}, err
	}
	return activity, nil
}

func readDeviceActivitySections(ctx context.Context, tx *sql.Tx, scope []any, addresses []string, activity *DeviceActivity) error {
	withLimit := func(limit int) []any { return append(append([]any(nil), scope...), limit+1) }
	truncated := false
	// Domains.
	rows, err := tx.QueryContext(ctx, deviceActivityDomainsStatement, withLimit(MaxDeviceActivityDomainRows)...)
	if err != nil {
		return fmt.Errorf("query device domains: %w", err)
	}
	scanned, err := scanDeviceActivityRows(rows, func(scan func(...any) error) error {
		var item DeviceDomainObservation
		if err := scan(&item.Domain, &item.Source, &item.Events, &item.FirstSeen, &item.LastSeen); err != nil {
			return err
		}
		host, ok := ActivityHost(item.Domain)
		if !ok {
			return nil
		}
		item.Domain = host
		item.FirstSeen, item.LastSeen = item.FirstSeen.UTC(), item.LastSeen.UTC()
		activity.Domains = append(activity.Domains, item)
		return nil
	})
	if err != nil {
		return fmt.Errorf("read device domains: %w", err)
	}
	if scanned > MaxDeviceActivityDomainRows {
		truncated = true
	}
	if len(activity.Domains) > MaxDeviceActivityDomainRows {
		activity.Domains = activity.Domains[:MaxDeviceActivityDomainRows]
	}
	activity.Domains = mergeDeviceDomainRows(activity.Domains)
	// Flow groups.
	if addresses == nil {
		addresses = []string{}
	}
	rows, err = tx.QueryContext(ctx, deviceActivityFlowsStatement, append(withLimit(MaxDeviceActivityFlowGroups), addresses)...)
	if err != nil {
		return fmt.Errorf("query device flows: %w", err)
	}
	scanned, err = scanDeviceActivityRows(rows, func(scan func(...any) error) error {
		var item DeviceFlowGroup
		var source string
		var serverPort, clientPort int64
		if err := scan(&source, &item.Transport, &item.Service, &serverPort, &clientPort, &item.Inbound, &item.Flows, &item.Bytes, &item.Peers, &item.SamplePeer, &item.FirstSeen, &item.LastSeen, &item.Intercepted); err != nil {
			return err
		}
		item.Source = Source(source)
		item.ServerPort, item.ClientPort = int(serverPort), int(clientPort)
		if address, err := netip.ParseAddr(item.SamplePeer); err == nil {
			item.SamplePeer = address.String()
		} else {
			item.SamplePeer = ""
		}
		item.Transport = strings.ToLower(item.Transport)
		item.Service = boundedActivityText(strings.ToLower(item.Service), 64)
		item.FirstSeen, item.LastSeen = item.FirstSeen.UTC(), item.LastSeen.UTC()
		if _, ok := activityTransportValues[item.Transport]; !ok {
			item.Transport = ""
		}
		activity.FlowGroups = append(activity.FlowGroups, item)
		return nil
	})
	if err != nil {
		return fmt.Errorf("read device flows: %w", err)
	}
	if scanned > MaxDeviceActivityFlowGroups {
		truncated = true
	}
	if len(activity.FlowGroups) > MaxDeviceActivityFlowGroups {
		activity.FlowGroups = activity.FlowGroups[:MaxDeviceActivityFlowGroups]
	}
	// TLS interception outcomes by host.
	rows, err = tx.QueryContext(ctx, deviceActivityTLSHostsStatement, withLimit(MaxDeviceActivityTLSHosts)...)
	if err != nil {
		return fmt.Errorf("query device TLS hosts: %w", err)
	}
	scanned, err = scanDeviceActivityRows(rows, func(scan func(...any) error) error {
		var item DeviceTLSHost
		if err := scan(&item.Host, &item.State, &item.FailureReason, &item.PinningSuspected, &item.Events, &item.FirstSeen, &item.LastSeen); err != nil {
			return err
		}
		host, ok := ActivityHost(item.Host)
		if !ok {
			host = ""
		}
		item.Host = host
		item.FailureReason = tlsReason(item.FailureReason)
		item.FirstSeen, item.LastSeen = item.FirstSeen.UTC(), item.LastSeen.UTC()
		activity.TLSHosts = append(activity.TLSHosts, item)
		return nil
	})
	if err != nil {
		return fmt.Errorf("read device TLS hosts: %w", err)
	}
	if scanned > MaxDeviceActivityTLSHosts {
		truncated = true
	}
	if len(activity.TLSHosts) > MaxDeviceActivityTLSHosts {
		activity.TLSHosts = activity.TLSHosts[:MaxDeviceActivityTLSHosts]
	}
	// Legacy TLS versions.
	rows, err = tx.QueryContext(ctx, deviceActivityTLSVersionsStatement, withLimit(MaxDeviceActivityTLSVersions)...)
	if err != nil {
		return fmt.Errorf("query device TLS versions: %w", err)
	}
	scanned, err = scanDeviceActivityRows(rows, func(scan func(...any) error) error {
		var item DeviceTLSVersion
		if err := scan(&item.Version, &item.Host, &item.Events, &item.FirstSeen, &item.LastSeen); err != nil {
			return err
		}
		version := LegacyTLSVersionLabel(item.Version)
		if version == "" {
			return nil
		}
		item.Version = version
		if host, ok := ActivityHost(item.Host); ok {
			item.Host = host
		} else {
			item.Host = ""
		}
		item.FirstSeen, item.LastSeen = item.FirstSeen.UTC(), item.LastSeen.UTC()
		activity.TLSVersions = append(activity.TLSVersions, item)
		return nil
	})
	if err != nil {
		return fmt.Errorf("read device TLS versions: %w", err)
	}
	if scanned > MaxDeviceActivityTLSVersions {
		truncated = true
	}
	if len(activity.TLSVersions) > MaxDeviceActivityTLSVersions {
		activity.TLSVersions = activity.TLSVersions[:MaxDeviceActivityTLSVersions]
	}
	// Cleartext HTTP hosts.
	rows, err = tx.QueryContext(ctx, deviceActivityCleartextHTTPStatement, withLimit(MaxDeviceActivityHTTPHosts)...)
	if err != nil {
		return fmt.Errorf("query device cleartext HTTP: %w", err)
	}
	scanned, err = scanDeviceActivityRows(rows, func(scan func(...any) error) error {
		var item DeviceHTTPHost
		if err := scan(&item.Host, &item.Requests, &item.SampleAddress, &item.FirstSeen, &item.LastSeen); err != nil {
			return err
		}
		host, ok := ActivityHost(item.Host)
		if !ok {
			return nil
		}
		item.Host = host
		if address, err := netip.ParseAddr(item.SampleAddress); err != nil {
			item.SampleAddress = ""
		} else {
			item.SampleAddress = address.String()
		}
		item.FirstSeen, item.LastSeen = item.FirstSeen.UTC(), item.LastSeen.UTC()
		activity.CleartextHTTP = append(activity.CleartextHTTP, item)
		return nil
	})
	if err != nil {
		return fmt.Errorf("read device cleartext HTTP: %w", err)
	}
	if scanned > MaxDeviceActivityHTTPHosts {
		truncated = true
	}
	if len(activity.CleartextHTTP) > MaxDeviceActivityHTTPHosts {
		activity.CleartextHTTP = activity.CleartextHTTP[:MaxDeviceActivityHTTPHosts]
	}
	// HTTP status classes.
	rows, err = tx.QueryContext(ctx, deviceActivityHTTPStatusStatement, scope...)
	if err != nil {
		return fmt.Errorf("query device HTTP status: %w", err)
	}
	scanned, err = scanDeviceActivityRows(rows, func(scan func(...any) error) error {
		var item DeviceHTTPStatusCount
		var source string
		if err := scan(&source, &item.Cleartext, &item.Class, &item.Count); err != nil {
			return err
		}
		item.Source = Source(source)
		activity.HTTPStatus = append(activity.HTTPStatus, item)
		return nil
	})
	if err != nil {
		return fmt.Errorf("read device HTTP status: %w", err)
	}
	// Alerts.
	rows, err = tx.QueryContext(ctx, deviceActivityAlertsStatement, withLimit(MaxDeviceActivityAlerts)...)
	if err != nil {
		return fmt.Errorf("query device alerts: %w", err)
	}
	scanned, err = scanDeviceActivityRows(rows, func(scan func(...any) error) error {
		var item DeviceAlertGroup
		if err := scan(&item.Engine, &item.Signature, &item.Severity, &item.Category, &item.Count, &item.FirstSeen, &item.LastSeen); err != nil {
			return err
		}
		item.Signature = boundedActivityText(item.Signature, maxDeviceActivityTextBytes)
		item.Category = boundedActivityText(item.Category, 128)
		item.Severity = findingSeverityLabel(item.Engine, item.Severity)
		if item.Signature == "" {
			return nil
		}
		item.FirstSeen, item.LastSeen = item.FirstSeen.UTC(), item.LastSeen.UTC()
		activity.Alerts = append(activity.Alerts, item)
		return nil
	})
	if err != nil {
		return fmt.Errorf("read device alerts: %w", err)
	}
	if scanned > MaxDeviceActivityAlerts {
		truncated = true
	}
	if len(activity.Alerts) > MaxDeviceActivityAlerts {
		activity.Alerts = activity.Alerts[:MaxDeviceActivityAlerts]
	}
	// Encrypted DNS resolvers.
	rows, err = tx.QueryContext(ctx, deviceActivityResolversStatement, withLimit(MaxDeviceActivityResolvers)...)
	if err != nil {
		return fmt.Errorf("query device encrypted DNS: %w", err)
	}
	scanned, err = scanDeviceActivityRows(rows, func(scan func(...any) error) error {
		var item DeviceResolver
		if err := scan(&item.Host, &item.Transport, &item.Events, &item.FirstSeen, &item.LastSeen); err != nil {
			return err
		}
		if host, ok := ActivityHost(item.Host); ok {
			item.Host = host
		} else {
			item.Host = ""
		}
		switch item.Transport {
		case "DOH", "DOT", "DOQ":
		default:
			item.Transport = "DOH"
		}
		item.FirstSeen, item.LastSeen = item.FirstSeen.UTC(), item.LastSeen.UTC()
		activity.EncryptedDNS = append(activity.EncryptedDNS, item)
		return nil
	})
	if err != nil {
		return fmt.Errorf("read device encrypted DNS: %w", err)
	}
	if scanned > MaxDeviceActivityResolvers {
		truncated = true
	}
	if len(activity.EncryptedDNS) > MaxDeviceActivityResolvers {
		activity.EncryptedDNS = activity.EncryptedDNS[:MaxDeviceActivityResolvers]
	}
	activity.Truncated = truncated
	return nil
}

// scanDeviceActivityRows calls each for every row and returns how many rows
// the database produced, so truncation is detected before invalid rows are
// skipped.
func scanDeviceActivityRows(rows *sql.Rows, each func(func(...any) error) error) (int, error) {
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if err := each(rows.Scan); err != nil {
			return count, err
		}
	}
	return count, rows.Err()
}

// mergeDeviceDomainRows collapses rows that normalized to the same domain and
// source (for example "Example.com." and "example.com").
func mergeDeviceDomainRows(items []DeviceDomainObservation) []DeviceDomainObservation {
	index := make(map[string]int, len(items))
	merged := items[:0]
	for _, item := range items {
		key := item.Source + "\x00" + item.Domain
		if position, ok := index[key]; ok {
			existing := &merged[position]
			existing.Events += item.Events
			if item.FirstSeen.Before(existing.FirstSeen) {
				existing.FirstSeen = item.FirstSeen
			}
			if item.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = item.LastSeen
			}
			continue
		}
		index[key] = len(merged)
		merged = append(merged, item)
	}
	return merged
}

// ActivityHost normalizes a DNS name, TLS server name, or HTTP host into a
// bounded lowercase host without a port or trailing dot. IP literals are
// returned in canonical form.
func ActivityHost(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 260 {
		return "", false
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.Index(value, "]"); end > 0 {
			value = value[1:end]
		}
	} else if strings.Count(value, ":") == 1 {
		host, port, _ := strings.Cut(value, ":")
		if _, err := strconv.Atoi(port); err == nil {
			value = host
		}
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Unmap().String(), true
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 || !activityHostPattern.MatchString(value) {
		return "", false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 {
			return "", false
		}
	}
	return value, true
}

// LegacyTLSVersionLabel maps Zeek ("TLSv10") and Suricata ("TLS 1.0")
// version spellings, already uppercased with spaces and dots removed, to a
// display label. It returns "" for TLS 1.2 and newer.
func LegacyTLSVersionLabel(normalized string) string {
	switch strings.ToUpper(strings.NewReplacer(" ", "", ".", "").Replace(normalized)) {
	case "SSLV2":
		return "SSLv2"
	case "SSLV3":
		return "SSLv3"
	case "TLSV1", "TLSV10", "TLS10":
		return "TLSv1.0"
	case "TLSV11", "TLS11":
		return "TLSv1.1"
	case "DTLSV10", "DTLS10":
		return "DTLSv1.0"
	default:
		return ""
	}
}

// findingSeverityLabel maps Suricata numeric priorities (1 highest) and ShakerProxy
// detection severities onto CRITICAL/HIGH/MEDIUM/LOW.
func findingSeverityLabel(engine, value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if engine == "SHAKERPROXY" {
		switch value {
		case "CRITICAL":
			return "CRITICAL"
		case "HIGH":
			return "HIGH"
		default:
			return "MEDIUM"
		}
	}
	switch value {
	case "1":
		return "HIGH"
	case "2":
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func boundedActivityText(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "")
	}
	var builder strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			character = ' '
		}
		if builder.Len()+utf8.RuneLen(character) > maximum {
			break
		}
		builder.WriteRune(character)
	}
	return strings.TrimSpace(builder.String())
}

func validDeviceActivityTime(value, start, end time.Time) bool {
	return !value.IsZero() && !value.Before(start) && value.Before(end)
}

// Validate checks the internal service contract on both sides of the
// ingestd-to-control-api boundary.
func (activity DeviceActivity) Validate(query DeviceActivityQuery) error {
	if err := validateDeviceActivityQuery(query); err != nil {
		return err
	}
	if activity.Schema != SchemaVersion || activity.GeneratedAt.Year() < 2000 || activity.GeneratedAt.Year() > 3000 || activity.DeviceID != query.DeviceID || !activity.Start.Equal(query.Start) || !activity.End.Equal(query.End) {
		return errors.New("device activity boundary is invalid")
	}
	counts := activity.Counts
	for _, value := range []int64{counts.Events, counts.ZeekConnections, counts.ZeekConnectionBytes, counts.SuricataFlows, counts.SuricataFlowBytes, counts.ZeekDNS, counts.SuricataDNS, counts.ZeekTLS, counts.SuricataTLS, counts.InterceptorTLS, counts.TLSIntercepted, counts.TLSBypassed, counts.TLSFailed, counts.TLSPinningSuspected, counts.InterceptorHTTPRequests, counts.InterceptorCleartextRequests, counts.ZeekHTTP, counts.SuricataHTTP, counts.Alerts, counts.EncryptedDNSDetections} {
		if value < 0 {
			return errors.New("device activity counts are invalid")
		}
	}
	if len(activity.Domains) > MaxDeviceActivityDomainRows || len(activity.FlowGroups) > MaxDeviceActivityFlowGroups || len(activity.TLSHosts) > MaxDeviceActivityTLSHosts || len(activity.TLSVersions) > MaxDeviceActivityTLSVersions || len(activity.CleartextHTTP) > MaxDeviceActivityHTTPHosts || len(activity.HTTPStatus) > 20 || len(activity.Alerts) > MaxDeviceActivityAlerts || len(activity.EncryptedDNS) > MaxDeviceActivityResolvers {
		return errors.New("device activity sections exceed their bounds")
	}
	if activity.Domains == nil || activity.FlowGroups == nil || activity.TLSHosts == nil || activity.TLSVersions == nil || activity.CleartextHTTP == nil || activity.HTTPStatus == nil || activity.Alerts == nil || activity.EncryptedDNS == nil {
		return errors.New("device activity sections are missing")
	}
	start, end := activity.Start, activity.End
	for _, item := range activity.Domains {
		if host, ok := ActivityHost(item.Domain); !ok || host != item.Domain || item.Source != DeviceDomainSourceDNS && item.Source != DeviceDomainSourceTLS && item.Source != DeviceDomainSourceHTTP || item.Events < 1 || !validDeviceActivityTime(item.FirstSeen, start, end) || !validDeviceActivityTime(item.LastSeen, start, end) || item.LastSeen.Before(item.FirstSeen) {
			return errors.New("device activity domain is invalid")
		}
	}
	for _, item := range activity.FlowGroups {
		if _, ok := activityTransportValues[item.Transport]; !ok || item.Source != SourceZeek && item.Source != SourceSuricata && item.Source != SourceMitmproxy || item.ServerPort < 0 || item.ServerPort > 65535 || item.ClientPort < 0 || item.ClientPort > 1023 || item.Flows < 1 || item.Bytes < 0 || item.Peers < 0 || len(item.Service) > 64 || !utf8.ValidString(item.Service) || !validDeviceActivityTime(item.FirstSeen, start, end) || !validDeviceActivityTime(item.LastSeen, start, end) {
			return errors.New("device activity flow group is invalid")
		}
		if item.SamplePeer != "" {
			if address, err := netip.ParseAddr(item.SamplePeer); err != nil || address.String() != item.SamplePeer {
				return errors.New("device activity flow peer is invalid")
			}
		}
	}
	for _, item := range activity.TLSHosts {
		if item.Host != "" {
			if host, ok := ActivityHost(item.Host); !ok || host != item.Host {
				return errors.New("device activity TLS host is invalid")
			}
		}
		if item.State != "INTERCEPTED" && item.State != "BYPASSED" && item.State != "FAILED" || item.FailureReason != "" && tlsReason(item.FailureReason) != item.FailureReason || item.Events < 1 || !validDeviceActivityTime(item.FirstSeen, start, end) || !validDeviceActivityTime(item.LastSeen, start, end) {
			return errors.New("device activity TLS outcome is invalid")
		}
	}
	for _, item := range activity.TLSVersions {
		if LegacyTLSVersionLabel(item.Version) != item.Version || item.Events < 1 || !validDeviceActivityTime(item.FirstSeen, start, end) || !validDeviceActivityTime(item.LastSeen, start, end) {
			return errors.New("device activity TLS version is invalid")
		}
		if item.Host != "" {
			if host, ok := ActivityHost(item.Host); !ok || host != item.Host {
				return errors.New("device activity TLS version host is invalid")
			}
		}
	}
	for _, item := range activity.CleartextHTTP {
		if host, ok := ActivityHost(item.Host); !ok || host != item.Host || item.Requests < 1 || !validDeviceActivityTime(item.FirstSeen, start, end) || !validDeviceActivityTime(item.LastSeen, start, end) {
			return errors.New("device activity cleartext HTTP host is invalid")
		}
		if item.SampleAddress != "" {
			if address, err := netip.ParseAddr(item.SampleAddress); err != nil || address.String() != item.SampleAddress {
				return errors.New("device activity cleartext HTTP address is invalid")
			}
		}
	}
	for _, item := range activity.HTTPStatus {
		if item.Source != SourceZeek && item.Source != SourceSuricata && item.Source != SourceMitmproxy || item.Source != SourceMitmproxy && !item.Cleartext || item.Count < 1 {
			return errors.New("device activity HTTP status is invalid")
		}
		switch item.Class {
		case "1xx", "2xx", "3xx", "4xx", "5xx":
		default:
			return errors.New("device activity HTTP status class is invalid")
		}
	}
	for _, item := range activity.Alerts {
		if item.Engine != "SURICATA" && item.Engine != "SHAKERPROXY" || boundedActivityText(item.Signature, maxDeviceActivityTextBytes) != item.Signature || item.Signature == "" || boundedActivityText(item.Category, 128) != item.Category || item.Count < 1 || !validDeviceActivityTime(item.FirstSeen, start, end) || !validDeviceActivityTime(item.LastSeen, start, end) {
			return errors.New("device activity alert is invalid")
		}
		switch item.Severity {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		default:
			return errors.New("device activity alert severity is invalid")
		}
	}
	for _, item := range activity.EncryptedDNS {
		if item.Host != "" {
			if host, ok := ActivityHost(item.Host); !ok || host != item.Host {
				return errors.New("device activity resolver host is invalid")
			}
		}
		if item.Transport != "DOH" && item.Transport != "DOT" && item.Transport != "DOQ" || item.Events < 1 || !validDeviceActivityTime(item.FirstSeen, start, end) || !validDeviceActivityTime(item.LastSeen, start, end) {
			return errors.New("device activity resolver is invalid")
		}
	}
	return nil
}
