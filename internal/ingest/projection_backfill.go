package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	// MaxProjectionBackfillBatch bounds one backfill pass.
	MaxProjectionBackfillBatch = 1000
	// ProjectionBackfillHorizon limits the backfill to recent history; older
	// rows keep their original columns and remain searchable by payload.
	ProjectionBackfillHorizon = 30 * 24 * time.Hour
)

// BackfillProjection classifies up to limit rows stored before
// projection_version existed or by an older projection, newest first, back to
// since. It only fills
// columns: new protocol, HTTP, alert, and DNS answer columns are written, and an
// existing service, DNS, or TLS value is never overwritten. It returns the number of
// rows it projected; zero means the backfill is complete for the horizon.
func (s PostgresSink) BackfillProjection(ctx context.Context, since time.Time, limit int) (int, error) {
	if s.DB == nil {
		return 0, errors.New("PostgreSQL connection is required")
	}
	if limit < 1 || limit > MaxProjectionBackfillBatch || since.IsZero() {
		return 0, errors.New("projection backfill bounds are invalid")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin projection backfill: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT record_id, occurred_at, source, kind, payload::text
FROM normalized_events
WHERE (projection_version IS NULL OR projection_version < $3) AND occurred_at >= $1
ORDER BY occurred_at DESC, record_id DESC
LIMIT $2`, since.UTC(), limit, ProjectionVersion)
	if err != nil {
		return 0, fmt.Errorf("select rows for projection backfill: %w", err)
	}
	type candidate struct {
		recordID   string
		occurredAt time.Time
		envelope   Envelope
	}
	candidates := make([]candidate, 0, limit)
	for rows.Next() {
		var row candidate
		var payload string
		if err := rows.Scan(&row.recordID, &row.occurredAt, &row.envelope.Source, &row.envelope.Kind, &payload); err != nil {
			rows.Close()
			return 0, fmt.Errorf("decode projection backfill row: %w", err)
		}
		row.envelope.Payload = []byte(payload)
		row.envelope.OccurredAt = row.occurredAt
		candidates = append(candidates, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("read projection backfill rows: %w", err)
	}
	rows.Close()
	for _, row := range candidates {
		projection := ProjectEvent(row.envelope)
		network, dns, tls, http, alert, protocol := projection.Network, projection.DNS, projection.TLS, projection.HTTP, projection.Alert, projection.Protocol
		var exotic any
		if protocol.Present() {
			exotic = protocol.Exotic
		}
		if _, err := tx.ExecContext(ctx, `UPDATE normalized_events SET
service = COALESCE(service, NULLIF($3,'')),
dns_query = COALESCE(dns_query, NULLIF($4,'')),
dns_record_type = COALESCE(dns_record_type, NULLIF($5,'')),
dns_answers = COALESCE(dns_answers, $20::text[]),
tls_server_name = COALESCE(tls_server_name, NULLIF($6,'')),
http_method = NULLIF($7,''), http_host = NULLIF($8,''), http_path = NULLIF($9,''), http_status = NULLIF($10::smallint,0),
alert_signature = NULLIF($11,''), alert_severity = NULLIF($12::smallint,0), alert_category = NULLIF($13,''),
app_protocol = NULLIF($14,''), protocol_category = NULLIF($15,''), protocol_visibility = NULLIF($16,''),
protocol_evidence = NULLIF($17,''), protocol_exotic = $18::boolean, projection_version = $19::smallint
WHERE occurred_at = $1 AND record_id = $2 AND (projection_version IS NULL OR projection_version < $19::smallint)`,
			row.occurredAt, row.recordID, network.Service, dns.Query, dns.RecordType, tls.ServerName,
			http.Method, http.Host, http.Path, http.Status, alert.Signature, alert.Severity, alert.Category,
			protocol.AppProtocol, protocol.Category, protocol.Visibility, protocol.Evidence, exotic, ProjectionVersion, dnsAnswersArgument(dns.Answers)); err != nil {
			return 0, fmt.Errorf("backfill normalized event projection: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit projection backfill: %w", err)
	}
	return len(candidates), nil
}
