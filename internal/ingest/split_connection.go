package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Each capture segment (30 seconds) is analyzed by its own Zeek run. A
// connection that outlives its segment is logged again in every later segment
// that carries its packets, under a new uid and without its handshake, so
// without the TLS server name: one HTTPS download to www.amazon.com became a
// named row, an unnamed row with most of the bytes, and a row for the final
// reset. A later record of the same connection takes the earlier record's
// flow ID and server name, so all of its records describe one named flow.
const (
	// A TCP record without a SYN cannot start a connection, so it continues
	// the latest earlier record of its 5-tuple even after a long idle gap
	// (push-notification connections send a keepalive every few minutes).
	splitTCPLookback = time.Hour
	// UDP has no handshake. Zeek itself ends an idle UDP flow after a minute,
	// so only a record from an adjacent segment continues it.
	splitUDPLookback = 2 * time.Minute
)

const splitConnectionLookupStatement = `SELECT COALESCE(flow_id, ''), COALESCE(tls_server_name, '') FROM normalized_events
WHERE capture_session_id = $1 AND source = 'ZEEK' AND kind = 'zeek.conn'
AND occurred_at < $2 AND occurred_at >= $3 AND protocol = $4
AND source_ip = $5::inet AND source_port = $6 AND destination_ip = $7::inet AND destination_port = $8
ORDER BY occurred_at DESC LIMIT 1`

// splitConnectionLookback reports how far back an earlier record of the same
// connection may be, or false when the record cannot continue one.
func splitConnectionLookback(envelope Envelope, network NetworkProjection) (time.Duration, bool) {
	if envelope.Source != SourceZeek || envelope.Kind != "zeek.conn" || envelope.CaptureSessionID == "" {
		return 0, false
	}
	if network.SourceIP == "" || network.DestinationIP == "" || network.SourcePort == 0 || network.DestinationPort == 0 {
		return 0, false
	}
	switch network.Protocol {
	case "tcp":
		var record struct {
			History string `json:"history"`
		}
		// A SYN from either side starts a connection, including a new one that
		// reuses the 5-tuple.
		if json.Unmarshal(envelope.Payload, &record) != nil || strings.ContainsAny(record.History, "Ss") {
			return 0, false
		}
		return splitTCPLookback, true
	case "udp":
		return splitUDPLookback, true
	}
	return 0, false
}

// linkSplitConnection gives a continuation record the flow ID and server name
// of the earlier record of its connection in the same capture.
func linkSplitConnection(ctx context.Context, tx *sql.Tx, envelope *Envelope, projection *EventProjection) error {
	lookback, ok := splitConnectionLookback(*envelope, projection.Network)
	if !ok {
		return nil
	}
	network := projection.Network
	var flowID, serverName string
	err := tx.QueryRowContext(ctx, splitConnectionLookupStatement, envelope.CaptureSessionID, envelope.OccurredAt, envelope.OccurredAt.Add(-lookback),
		network.Protocol, network.SourceIP, network.SourcePort, network.DestinationIP, network.DestinationPort).Scan(&flowID, &serverName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find the earlier record of a split connection: %w", err)
	}
	if flowID != "" {
		envelope.FlowID = flowID
	}
	if projection.TLS.ServerName == "" {
		projection.TLS.ServerName = serverName
	}
	return nil
}
