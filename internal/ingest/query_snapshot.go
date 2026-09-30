package ingest

import (
	"context"
	"errors"
	"regexp"
	"time"
)

const (
	QuerySnapshotSchemaVersion = 1
	QuerySnapshotPolicyVersion = "event-query-v1"
	DefaultQuerySnapshotTTL    = 15 * time.Minute
	MinQuerySnapshotTTL        = time.Minute
	MaxQuerySnapshotTTL        = time.Hour
	MaxActiveQuerySnapshots    = 20
	MaxQuerySnapshotCountScan  = 100_000
)

var (
	ErrQuerySnapshotNotFound = errors.New("event query snapshot not found or expired")
	ErrQuerySnapshotLimit    = errors.New("active event query snapshot limit reached")
	querySnapshotIDPattern   = regexp.MustCompile(`^qsnap-[a-f0-9]{32}$`)
	querySnapshotSHA256      = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type EventQuerySort struct {
	Field     string `json:"field"`
	Direction string `json:"direction"`
}

func DefaultEventQuerySort() []EventQuerySort {
	return []EventQuerySort{{Field: "occurred_at", Direction: "desc"}, {Field: "record_id", Direction: "desc"}}
}

type EventQuerySnapshotInput struct {
	Query            string           `json:"query"`
	Sort             []EventQuerySort `json:"sort"`
	ExpiresInSeconds int              `json:"expires_in_seconds,omitempty"`
}

type EventDatasetWatermark struct {
	IngestSequence int64     `json:"ingest_sequence"`
	ReceivedAt     time.Time `json:"received_at"`
	RecordID       string    `json:"record_id"`
}

type EventQuerySnapshot struct {
	Schema           int                   `json:"schema"`
	ID               string                `json:"query_snapshot_id"`
	CanonicalQuery   string                `json:"canonical_query"`
	Sort             []EventQuerySort      `json:"sort"`
	QueryAnchor      *time.Time            `json:"query_anchor,omitempty"`
	MatchedCount     int64                 `json:"matched_count"`
	CountRelation    string                `json:"count_relation"`
	CreatedAt        time.Time             `json:"created_at"`
	ExpiresAt        time.Time             `json:"expires_at"`
	DatasetWatermark EventDatasetWatermark `json:"dataset_watermark"`
	SnapshotSHA256   string                `json:"snapshot_sha256"`
	PolicyVersion    string                `json:"policy_version"`
}

type EventQuerySnapshotRepository interface {
	CreateEventQuerySnapshot(context.Context, string, string, RecentEventQuery, time.Duration) (EventQuerySnapshot, error)
	GetEventQuerySnapshot(context.Context, string, string) (EventQuerySnapshot, error)
}

type ResolvedEventQuerySnapshot struct {
	Snapshot EventQuerySnapshot
	Query    RecentEventQuery
}

func ValidQuerySnapshotID(value string) bool { return querySnapshotIDPattern.MatchString(value) }

func ValidateEventQuerySort(sort []EventQuerySort) error {
	if len(sort) != 2 || sort[0].Field != "occurred_at" || sort[0].Direction != "desc" || sort[1].Field != "record_id" || sort[1].Direction != "desc" {
		return errors.New("event query snapshot sort must be occurred_at DESC, record_id DESC")
	}
	return nil
}

func ValidateEventQuerySnapshot(snapshot EventQuerySnapshot) error {
	if snapshot.Schema != QuerySnapshotSchemaVersion || !ValidQuerySnapshotID(snapshot.ID) || len(snapshot.CanonicalQuery) > 2048 || ValidateEventQuerySort(snapshot.Sort) != nil || snapshot.MatchedCount < 0 || snapshot.MatchedCount > MaxQuerySnapshotCountScan || snapshot.CountRelation != "eq" && snapshot.CountRelation != "gte" || snapshot.CountRelation == "gte" && snapshot.MatchedCount != MaxQuerySnapshotCountScan || snapshot.CreatedAt.IsZero() || snapshot.ExpiresAt.Sub(snapshot.CreatedAt) < MinQuerySnapshotTTL || snapshot.ExpiresAt.Sub(snapshot.CreatedAt) > MaxQuerySnapshotTTL || snapshot.DatasetWatermark.IngestSequence < 0 || snapshot.DatasetWatermark.ReceivedAt.IsZero() || !validRecordID(snapshot.DatasetWatermark.RecordID) || !querySnapshotSHA256.MatchString(snapshot.SnapshotSHA256) || snapshot.PolicyVersion != QuerySnapshotPolicyVersion {
		return errors.New("event query snapshot is invalid")
	}
	if snapshot.QueryAnchor != nil && (snapshot.QueryAnchor.IsZero() || snapshot.QueryAnchor.Before(snapshot.CreatedAt.Add(-time.Second)) || snapshot.QueryAnchor.After(snapshot.CreatedAt.Add(time.Second))) {
		return errors.New("event query snapshot anchor is invalid")
	}
	return nil
}

func validSnapshotActor(value string) bool {
	if len(value) < 1 || len(value) > 96 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '@' || char == '-') {
			return false
		}
	}
	return true
}
