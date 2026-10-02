package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// NearbyWiFiRetention is how long Wi-Fi events about devices and networks
// that are not part of the lab (recorded only when the tester opts in) are
// kept.
const NearbyWiFiRetention = 24 * time.Hour

const nearbyWiFiPruneInterval = 10 * time.Minute

// PruneNearbyWiFi deletes the nearby Wi-Fi events older than before, with
// their identity rows.
func (s PostgresSink) PruneNearbyWiFi(ctx context.Context, before time.Time) (int64, error) {
	if s.DB == nil || before.IsZero() {
		return 0, errors.New("nearby Wi-Fi pruning is not configured")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE nearby_wifi_targets ON COMMIT DROP AS
SELECT DISTINCT record_id FROM normalized_events
WHERE source = 'HOST' AND starts_with(kind, 'wifi.') AND payload->>'scope' = 'nearby' AND occurred_at < $1`, before.UTC()); err != nil {
		return 0, fmt.Errorf("select nearby Wi-Fi events: %w", err)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM normalized_events
WHERE source = 'HOST' AND starts_with(kind, 'wifi.') AND payload->>'scope' = 'nearby' AND occurred_at < $1`, before.UTC())
	if err != nil {
		return 0, fmt.Errorf("delete nearby Wi-Fi events: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM normalized_event_identities identity_row
USING nearby_wifi_targets target
WHERE identity_row.record_id = target.record_id
  AND NOT EXISTS (SELECT 1 FROM normalized_events remaining WHERE remaining.record_id = identity_row.record_id)`); err != nil {
		return 0, fmt.Errorf("delete nearby Wi-Fi event identities: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

// RunNearbyWiFiRetention prunes nearby Wi-Fi events every few minutes until
// ctx ends.
func RunNearbyWiFiRetention(ctx context.Context, sink PostgresSink, logger *slog.Logger) {
	ticker := time.NewTicker(nearbyWiFiPruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		pruneContext, cancel := context.WithTimeout(ctx, time.Minute)
		deleted, err := sink.PruneNearbyWiFi(pruneContext, time.Now().Add(-NearbyWiFiRetention))
		cancel()
		switch {
		case err != nil && logger != nil:
			logger.Warn("nearby Wi-Fi events could not be pruned", "error", err)
		case deleted > 0 && logger != nil:
			logger.Info("nearby Wi-Fi events past their retention were deleted", "events", deleted)
		}
	}
}
