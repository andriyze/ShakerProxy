package ingest

import (
	"context"
	"database/sql"
	"fmt"
)

// connectionNameLookback is how far back a client's DNS answer may name a
// connection it opens; long-lived apps reuse an answer for its TTL.
const connectionNameLookback = "30 minutes"

// nameHostConnections names the batch's gateway-reported connections
// (dns_name) by the most recent lookup in which the same client resolved the
// destination address. It runs after the batch's rows are inserted, so a
// lookup delivered in the same batch counts too.
func nameHostConnections(ctx context.Context, tx *sql.Tx, batch []PendingRecord) error {
	recordIDs := make([]string, 0, len(batch))
	for _, pending := range batch {
		if isHostConn(pending.Record.Envelope) {
			recordIDs = append(recordIDs, pending.RecordID)
		}
	}
	if len(recordIDs) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE normalized_events c SET dns_name = (
  SELECT d.dns_query FROM normalized_events d
   WHERE d.source_ip = c.source_ip
     AND d.dns_answers @> ARRAY[host(c.destination_ip)]
     AND d.kind IN ('`+HostDNSKind+`', 'zeek.dns')
     AND d.dns_query IS NOT NULL
     AND d.occurred_at BETWEEN c.occurred_at - interval '`+connectionNameLookback+`' AND c.occurred_at + interval '5 seconds'
   ORDER BY d.occurred_at DESC LIMIT 1)
 WHERE c.record_id = ANY($1) AND c.source = 'HOST' AND c.kind = '`+HostConnKind+`'
   AND c.source_ip IS NOT NULL AND c.destination_ip IS NOT NULL AND c.dns_name IS NULL`, recordIDs)
	if err != nil {
		return fmt.Errorf("name gateway-reported connections: %w", err)
	}
	return nil
}

// validDNSAnswerName accepts a dns_name copied from a stored dns_query.
func validDNSAnswerName(name string) bool { return validText(name, 1, 253) }
