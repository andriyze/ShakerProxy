package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

type internalEventQuerySnapshotRequest struct {
	Schema               int    `json:"schema"`
	PublicCanonicalQuery string `json:"public_canonical_query"`
	EncodedQuery         string `json:"encoded_query"`
	ExpiresInSeconds     int    `json:"expires_in_seconds"`
}

func (c *QueryClient) CreateEventQuerySnapshot(ctx context.Context, actor, publicCanonical string, query RecentEventQuery, lifetime time.Duration) (EventQuerySnapshot, error) {
	if c == nil || c.endpoint == nil || c.client == nil || !validSnapshotActor(actor) || lifetime < MinQuerySnapshotTTL || lifetime > MaxQuerySnapshotTTL || lifetime%time.Second != 0 {
		return EventQuerySnapshot{}, errors.New("event query snapshot client request is invalid")
	}
	publicFilter, err := querylang.Parse(publicCanonical)
	if err != nil || publicFilter.Canonical != publicCanonical {
		return EventQuerySnapshot{}, errors.New("event query snapshot filter is not canonical")
	}
	query.Limit = 1
	if err := validateRecentEventQuery(query); err != nil {
		return EventQuerySnapshot{}, err
	}
	storageQuery, err := prepareStorageRecentQuery(query)
	if err != nil {
		return EventQuerySnapshot{}, err
	}
	values, err := encodeInternalRecentEventQuery(storageQuery)
	if err != nil {
		return EventQuerySnapshot{}, err
	}
	payload := internalEventQuerySnapshotRequest{Schema: QuerySnapshotSchemaVersion, PublicCanonicalQuery: publicCanonical, EncodedQuery: values.Encode(), ExpiresInSeconds: int(lifetime / time.Second)}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > 48<<10 {
		return EventQuerySnapshot{}, errors.New("event query snapshot request is oversized")
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/event-query-snapshots"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return EventQuerySnapshot{}, errors.New("create event query snapshot request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("X-ShakerProxy-Actor", actor)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	snapshot, err := c.doEventQuerySnapshotRequest(request, http.StatusCreated)
	if err != nil {
		return EventQuerySnapshot{}, err
	}
	if snapshot.CanonicalQuery != publicCanonical || querylang.HasRelativeTime(query.Filter) != (snapshot.QueryAnchor != nil) || snapshot.ExpiresAt.Sub(snapshot.CreatedAt) != lifetime {
		return EventQuerySnapshot{}, errors.New("event query snapshot service returned a mismatched snapshot")
	}
	return snapshot, nil
}

func (c *QueryClient) GetEventQuerySnapshot(ctx context.Context, actor, id string) (EventQuerySnapshot, error) {
	if c == nil || c.endpoint == nil || c.client == nil || !validSnapshotActor(actor) || !ValidQuerySnapshotID(id) {
		return EventQuerySnapshot{}, errors.New("event query snapshot client lookup is invalid")
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/event-query-snapshots/" + id
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return EventQuerySnapshot{}, errors.New("create event query snapshot lookup")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("X-ShakerProxy-Actor", actor)
	request.Header.Set("Accept", "application/json")
	return c.doEventQuerySnapshotRequest(request, http.StatusOK)
}

func (c *QueryClient) doEventQuerySnapshotRequest(request *http.Request, expectedStatus int) (EventQuerySnapshot, error) {
	response, err := c.client.Do(request)
	if err != nil {
		return EventQuerySnapshot{}, fmt.Errorf("request event query snapshot service: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return EventQuerySnapshot{}, ErrQuerySnapshotNotFound
	}
	if response.StatusCode == http.StatusConflict {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return EventQuerySnapshot{}, ErrQuerySnapshotLimit
	}
	if response.StatusCode != expectedStatus {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return EventQuerySnapshot{}, fmt.Errorf("event query snapshot service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return EventQuerySnapshot{}, errors.New("event query snapshot service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: (32 << 10) + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var snapshot EventQuerySnapshot
	if err := decoder.Decode(&snapshot); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 || ValidateEventQuerySnapshot(snapshot) != nil {
		return EventQuerySnapshot{}, errors.New("event query snapshot service returned an invalid snapshot")
	}
	return snapshot, nil
}
