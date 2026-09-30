package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/pcapng"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

const (
	legacyDeviceTrafficPreviewSchema = 1
	deviceTrafficPreviewSchema       = 2
	deviceTrafficPreviewTTL          = 10 * time.Minute
	maxDeviceTrafficRange            = 30 * 24 * time.Hour
)

var errDeviceIdentityEvidenceUnavailable = errors.New("device identity evidence unavailable")

type deviceTrafficDeletionPreviewInput struct {
	StartAt time.Time `json:"start_at"`
	EndAt   time.Time `json:"end_at"`
}

type deviceTrafficChoiceImpact struct {
	Choice                     capture.SharedPCAPDisposition `json:"choice"`
	Eligible                   bool                          `json:"eligible"`
	ExecutionAvailable         bool                          `json:"execution_available"`
	NormalizedEventRows        int64                         `json:"normalized_event_rows"`
	CollateralEventRows        int64                         `json:"collateral_event_rows"`
	PCAPFilesDeleted           int                           `json:"pcap_files_deleted"`
	PCAPFilesRewritten         int                           `json:"pcap_files_rewritten"`
	MatchedPacketsRemoved      uint64                        `json:"matched_packets_removed"`
	CollateralPacketsRemoved   uint64                        `json:"collateral_packets_removed"`
	PCAPBytesReclaimable       int64                         `json:"pcap_bytes_reclaimable"`
	TemporaryBytesRequired     uint64                        `json:"temporary_bytes_required"`
	AnalyzerCheckpointsRemoved int                           `json:"analyzer_checkpoints_removed"`
	AnalyzerReplayBarriers     int                           `json:"analyzer_replay_barriers"`
	RequiresReindex            bool                          `json:"requires_reindex"`
	RetainsPacketBytes         bool                          `json:"retains_packet_bytes"`
	Warnings                   []string                      `json:"warnings"`
}

type deviceTrafficAnalyzerImpact struct {
	SessionID string                             `json:"session_id"`
	Zeek      analyzer.CheckpointDeletionPreview `json:"zeek"`
	Suricata  analyzer.CheckpointDeletionPreview `json:"suricata"`
}

type deviceTrafficDeletionPreview struct {
	Schema                      int                                  `json:"schema"`
	PreviewSHA256               string                               `json:"preview_sha256"`
	GeneratedAt                 time.Time                            `json:"generated_at"`
	ExpiresAt                   time.Time                            `json:"expires_at"`
	DeviceID                    string                               `json:"device_id"`
	DeviceName                  string                               `json:"device_name,omitempty"`
	StartAt                     time.Time                            `json:"start_at"`
	EndAt                       time.Time                            `json:"end_at"`
	InventoryEvidenceAsOf       time.Time                            `json:"inventory_evidence_as_of"`
	IdentityEvidenceCoversRange bool                                 `json:"identity_evidence_covers_range"`
	CapabilityLimitations       []string                             `json:"capability_limitations"`
	NormalizedEvents            ingest.EventQuerySnapshot            `json:"normalized_events"`
	NormalizedEventDeletion     ingest.EventSelectionDeletionBundle  `json:"normalized_event_deletion"`
	WholeCaptureEvents          []ingest.CaptureEventDeletionPreview `json:"whole_capture_events"`
	PCAP                        capture.PCAPSelectionImpact          `json:"pcap"`
	AnalyzerReindex             []deviceTrafficAnalyzerImpact        `json:"analyzer_reindex"`
	ExistingExportRecords       int                                  `json:"existing_export_records,omitempty"`
	CopyBoundaries              []deletionCopyBoundary               `json:"copy_boundaries,omitempty"`
	Choices                     []deviceTrafficChoiceImpact          `json:"choices"`
	ExactImpact                 bool                                 `json:"exact_impact"`
	SecureErasureGuaranteed     bool                                 `json:"secure_erasure_guaranteed"`
	Confirmation                string                               `json:"confirmation"`
}

type eventSelectionDeletionService interface {
	PreviewEventSelection(context.Context, ingest.EventSelectionDeletionPreviewRequest) (ingest.EventSelectionDeletionBundle, error)
	DeleteEventSelection(context.Context, ingest.EventSelectionDeletionRequest) (ingest.EventSelectionDeletionOutcome, error)
}

func (s *Server) previewDeviceTrafficDeletion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	deviceID := r.PathValue("deviceID")
	if !deviceinventory.ValidDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid_request", "device ID is invalid")
		return
	}
	var input deviceTrafficDeletionPreviewInput
	if err := decodeJSON(r, &input); err != nil {
		writeDecodeError(w, err, "device traffic deletion preview")
		return
	}
	input.StartAt, input.EndAt = input.StartAt.UTC(), input.EndAt.UTC()
	now := time.Now().UTC()
	if input.StartAt.IsZero() || !input.StartAt.Before(input.EndAt) || input.EndAt.Sub(input.StartAt) > maxDeviceTrafficRange || input.EndAt.After(now.Add(time.Minute)) {
		writeError(w, http.StatusBadRequest, "invalid_request", "device traffic range must be a valid historical interval of at most 30 days")
		return
	}
	if s.inventory == nil || s.eventSnapshots == nil || s.eventSelectionDeletions == nil {
		writeError(w, http.StatusServiceUnavailable, "deletion_preview_unavailable", "device inventory and coordinated event deletion are required")
		return
	}
	snapshot, err := s.inventory.Snapshot()
	if err != nil {
		s.logger.Warn("device deletion inventory snapshot failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "deletion_preview_unavailable", "device identity evidence is temporarily unavailable")
		return
	}
	device, selection, coversRange, conflicts, err := devicePCAPSelection(snapshot, deviceID, input.StartAt, input.EndAt)
	if errors.Is(err, errDeviceIdentityEvidenceUnavailable) {
		writeError(w, http.StatusUnprocessableEntity, "identity_evidence_unavailable", "device has no time-bounded MAC or IP evidence in the requested range")
		return
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "device_not_found", "device was not found")
		return
	}
	if len(conflicts) > 0 {
		writeError(w, http.StatusConflict, "identity_evidence_conflicted", "device identity evidence overlaps another device in the requested range")
		return
	}
	filterText := fmt.Sprintf("device.id:%s AND time>=%s AND time<%s", deviceID, input.StartAt.Format(time.RFC3339Nano), input.EndAt.Format(time.RFC3339Nano))
	filter, err := querylang.Parse(filterText)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "deletion_preview_failed", "device deletion filter could not be constructed")
		return
	}
	query := ingest.RecentEventQuery{Limit: 1, Filter: filter}
	previewContext, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	eventSnapshot, err := s.eventSnapshots.CreateEventQuerySnapshot(previewContext, sessionUsername(r.Context()), filter.Canonical, query, deviceTrafficPreviewTTL)
	if err != nil {
		s.writeEventQuerySnapshotError(w, err)
		return
	}
	if ingest.ValidateEventQuerySnapshot(eventSnapshot) != nil || eventSnapshot.CanonicalQuery != filter.Canonical {
		writeError(w, http.StatusServiceUnavailable, "deletion_preview_unavailable", "frozen normalized-event impact is invalid")
		return
	}
	if !eventSnapshot.ExpiresAt.After(time.Now().UTC()) {
		writeError(w, http.StatusServiceUnavailable, "deletion_preview_unavailable", "frozen normalized-event impact expired before the PCAP scan")
		return
	}
	var pcapImpact capture.PCAPSelectionImpact
	if err := s.gateway.CallWithTimeout(previewContext, "PreviewPCAPSelection", gatewayprotocol.PreviewPCAPSelectionParams{Selection: selection}, &pcapImpact, 2*time.Minute); err != nil || pcapImpact.Validate() != nil || pcapImpact.SelectionSHA256 != selectionDigest(selection) {
		s.logger.Warn("device deletion PCAP impact preview failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "deletion_preview_unavailable", "exact shared-PCAP impact is temporarily unavailable")
		return
	}
	eventSelection, err := eventSelectionFromPCAP(deviceID, input.StartAt, input.EndAt, selection)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "deletion_preview_failed", "normalized-event deletion selection could not be constructed")
		return
	}
	eventDeletion, err := s.eventSelectionDeletions.PreviewEventSelection(previewContext, ingest.EventSelectionDeletionPreviewRequest{Actor: sessionUsername(r.Context()), Selection: eventSelection, QuerySnapshot: eventSnapshot})
	if err != nil || eventDeletion.Validate() != nil || eventDeletion.QuerySnapshot.SnapshotSHA256 != eventSnapshot.SnapshotSHA256 || eventDeletion.Selection.DeviceID != deviceID {
		s.logger.Warn("device normalized-event deletion preview failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "deletion_preview_unavailable", "exact normalized-event deletion impact is temporarily unavailable")
		return
	}
	wholeCaptureEvents, err := s.previewDeviceTrafficCaptureEvents(previewContext, pcapImpact)
	if err != nil {
		s.logger.Warn("device whole-file event preview failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "deletion_preview_unavailable", "whole-file collateral event evidence is temporarily unavailable")
		return
	}
	analyzerImpacts, err := s.previewDeviceTrafficAnalyzers(previewContext, pcapImpact)
	if err != nil {
		s.logger.Warn("device analyzer reindex preview failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "deletion_preview_unavailable", "analyzer re-index evidence is temporarily unavailable")
		return
	}
	exportAuditRecords := 0
	for _, sessionID := range deviceTrafficSessions(pcapImpact) {
		records, exportErr := s.store.ListCaptureExports(sessionID)
		if exportErr != nil || len(records) > maxCaptureExportRecords-exportAuditRecords {
			s.logger.Warn("device deletion export boundary lookup failed", "capture_id", sessionID, "error", exportErr)
			writeError(w, http.StatusServiceUnavailable, "deletion_preview_unavailable", "export and backup boundaries are temporarily unavailable")
			return
		}
		exportAuditRecords += len(records)
	}
	generatedAt := time.Now().UTC()
	if !eventSnapshot.ExpiresAt.After(generatedAt) {
		writeError(w, http.StatusServiceUnavailable, "deletion_preview_unavailable", "frozen normalized-event impact expired during the PCAP scan")
		return
	}
	expiresAt := generatedAt.Add(deviceTrafficPreviewTTL)
	if eventSnapshot.ExpiresAt.Before(expiresAt) {
		expiresAt = eventSnapshot.ExpiresAt
	}
	if eventDeletion.ExpiresAt.Before(expiresAt) {
		expiresAt = eventDeletion.ExpiresAt
	}
	for _, impact := range wholeCaptureEvents {
		if impact.ExpiresAt.Before(expiresAt) {
			expiresAt = impact.ExpiresAt
		}
	}
	for _, impact := range analyzerImpacts {
		if impact.Zeek.ExpiresAt.Before(expiresAt) {
			expiresAt = impact.Zeek.ExpiresAt
		}
		if impact.Suricata.ExpiresAt.Before(expiresAt) {
			expiresAt = impact.Suricata.ExpiresAt
		}
	}
	choices, exact := buildDeviceTrafficChoices(eventDeletion, wholeCaptureEvents, analyzerImpacts, pcapImpact)
	preview := deviceTrafficDeletionPreview{
		Schema: deviceTrafficPreviewSchema, GeneratedAt: generatedAt, ExpiresAt: expiresAt, DeviceID: deviceID,
		DeviceName: device.FriendlyName, StartAt: input.StartAt, EndAt: input.EndAt, InventoryEvidenceAsOf: snapshot.EvidenceAsOf,
		IdentityEvidenceCoversRange: coversRange, CapabilityLimitations: []string{"time-bounded IPv6 device-address evidence is not yet indexed"},
		NormalizedEvents: eventSnapshot, NormalizedEventDeletion: eventDeletion, WholeCaptureEvents: wholeCaptureEvents, PCAP: pcapImpact, AnalyzerReindex: analyzerImpacts, ExistingExportRecords: exportAuditRecords, CopyBoundaries: deletionCopyBoundaries(exportAuditRecords), Choices: choices, ExactImpact: exact,
		SecureErasureGuaranteed: false, Confirmation: deviceID,
	}
	preview.PreviewSHA256, err = hashDeviceTrafficPreview(preview)
	if err != nil || preview.validate() != nil {
		writeError(w, http.StatusInternalServerError, "deletion_preview_failed", "device deletion preview could not be bound")
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) previewDeviceTrafficCaptureEvents(ctx context.Context, pcapImpact capture.PCAPSelectionImpact) ([]ingest.CaptureEventDeletionPreview, error) {
	sessions := deviceTrafficSessions(pcapImpact)
	if len(sessions) == 0 {
		return []ingest.CaptureEventDeletionPreview{}, nil
	}
	if s.captureEventDeletions == nil {
		return nil, errors.New("capture event deletion service is not configured")
	}
	result := make([]ingest.CaptureEventDeletionPreview, 0, len(sessions))
	for _, sessionID := range sessions {
		preview, err := s.captureEventDeletions.Preview(ctx, sessionID)
		if err != nil || preview.Validate() != nil || preview.CaptureSessionID != sessionID {
			return nil, errors.Join(errors.New("capture event deletion preview is inconsistent"), err)
		}
		result = append(result, preview)
	}
	return result, nil
}

func (s *Server) previewDeviceTrafficAnalyzers(ctx context.Context, pcapImpact capture.PCAPSelectionImpact) ([]deviceTrafficAnalyzerImpact, error) {
	sessions := deviceTrafficSessions(pcapImpact)
	if len(sessions) == 0 {
		return []deviceTrafficAnalyzerImpact{}, nil
	}
	if s.zeekCheckpointDeletions == nil || s.suricataCheckpointDeletions == nil {
		return nil, errors.New("analyzer maintenance services are not configured")
	}
	result := make([]deviceTrafficAnalyzerImpact, 0, len(sessions))
	for _, sessionID := range sessions {
		zeek, err := s.zeekCheckpointDeletions.Preview(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		suricata, err := s.suricataCheckpointDeletions.Preview(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		if zeek.Validate() != nil || suricata.Validate() != nil || zeek.Engine != analyzer.EngineZeek || suricata.Engine != analyzer.EngineSuricata || zeek.CaptureSessionID != sessionID || suricata.CaptureSessionID != sessionID {
			return nil, errors.New("analyzer maintenance preview is inconsistent")
		}
		result = append(result, deviceTrafficAnalyzerImpact{SessionID: sessionID, Zeek: zeek, Suricata: suricata})
	}
	return result, nil
}

func deviceTrafficSessions(pcapImpact capture.PCAPSelectionImpact) []string {
	sessions := make([]string, 0, len(pcapImpact.ImpactedFiles))
	for _, impact := range pcapImpact.ImpactedFiles {
		if len(sessions) == 0 || sessions[len(sessions)-1] != impact.SessionID {
			sessions = append(sessions, impact.SessionID)
		}
	}
	return sessions
}

func devicePCAPSelection(snapshot deviceinventory.Snapshot, deviceID string, startAt, endAt time.Time) (deviceinventory.Device, pcapng.SelectionRule, bool, []string, error) {
	var target *deviceinventory.Device
	for index := range snapshot.Devices {
		if snapshot.Devices[index].ID == deviceID {
			target = &snapshot.Devices[index]
			break
		}
	}
	if target == nil {
		return deviceinventory.Device{}, pcapng.SelectionRule{}, false, nil, errors.New("device not found")
	}
	identities := deviceSelectionIdentities(*target, startAt, endAt)
	if len(identities) == 0 {
		return *target, pcapng.SelectionRule{}, false, nil, errDeviceIdentityEvidenceUnavailable
	}
	conflicts := make([]string, 0)
	for _, other := range snapshot.Devices {
		if other.ID == deviceID {
			continue
		}
		for _, candidate := range deviceSelectionIdentities(other, startAt, endAt) {
			for _, selected := range identities {
				if selected.Kind == candidate.Kind && selected.Value == candidate.Value && identityWindowsOverlap(selected, candidate) {
					conflicts = append(conflicts, string(selected.Kind)+":"+selected.Value)
				}
			}
		}
	}
	sort.Strings(conflicts)
	conflicts = compactServerStrings(conflicts)
	rule, err := pcapng.CanonicalWindowedSelectionRule(identities)
	if err != nil {
		return *target, pcapng.SelectionRule{}, false, conflicts, err
	}
	return *target, rule, selectionCoversRange(rule, startAt, endAt), conflicts, nil
}

func deviceSelectionIdentities(device deviceinventory.Device, startAt, endAt time.Time) []pcapng.SelectionIdentity {
	identities := make([]pcapng.SelectionIdentity, 0, len(device.Identities)+len(device.Addresses))
	for _, identity := range device.Identities {
		if identity.Kind != deviceinventory.IdentityMAC {
			continue
		}
		identityEnd := identity.LastSeen.UTC()
		if identityEnd.Before(time.Date(9999, 12, 31, 23, 59, 59, 999999998, time.UTC)) {
			identityEnd = identityEnd.Add(time.Nanosecond)
		}
		if clippedStart, clippedEnd, ok := clipIdentityWindow(startAt, endAt, identity.FirstSeen.UTC(), identityEnd); ok {
			identities = append(identities, pcapng.SelectionIdentity{Kind: pcapng.SelectionIdentityMAC, Value: identity.Value, StartAt: &clippedStart, EndAt: &clippedEnd})
		}
	}
	for _, address := range device.Addresses {
		if clippedStart, clippedEnd, ok := clipIdentityWindow(startAt, endAt, address.ValidFrom.UTC(), address.ValidUntil.UTC()); ok {
			identities = append(identities, pcapng.SelectionIdentity{Kind: pcapng.SelectionIdentityIP, Value: address.Address, StartAt: &clippedStart, EndAt: &clippedEnd})
		}
	}
	return identities
}

func clipIdentityWindow(requestStart, requestEnd, evidenceStart, evidenceEnd time.Time) (time.Time, time.Time, bool) {
	start, end := requestStart, requestEnd
	if evidenceStart.After(start) {
		start = evidenceStart
	}
	if evidenceEnd.Before(end) {
		end = evidenceEnd
	}
	return start, end, start.Before(end)
}

func identityWindowsOverlap(left, right pcapng.SelectionIdentity) bool {
	return left.StartAt != nil && right.StartAt != nil && left.StartAt.Before(*right.EndAt) && right.StartAt.Before(*left.EndAt)
}

func selectionCoversRange(rule pcapng.SelectionRule, startAt, endAt time.Time) bool {
	windows := append([]pcapng.SelectionIdentity(nil), rule.Identities...)
	sort.Slice(windows, func(i, j int) bool { return windows[i].StartAt.Before(*windows[j].StartAt) })
	cursor := startAt
	for _, window := range windows {
		if window.StartAt.After(cursor) {
			continue
		}
		if window.EndAt.After(cursor) {
			cursor = *window.EndAt
		}
		if !cursor.Before(endAt) {
			return true
		}
	}
	return false
}

func buildDeviceTrafficChoices(events ingest.EventSelectionDeletionBundle, wholeCaptureEvents []ingest.CaptureEventDeletionPreview, analyzerImpacts []deviceTrafficAnalyzerImpact, pcapImpact capture.PCAPSelectionImpact) ([]deviceTrafficChoiceImpact, bool) {
	return buildDeviceTrafficChoicesForSchema(deviceTrafficPreviewSchema, events, wholeCaptureEvents, analyzerImpacts, pcapImpact)
}

func buildDeviceTrafficChoicesForSchema(schema int, events ingest.EventSelectionDeletionBundle, wholeCaptureEvents []ingest.CaptureEventDeletionPreview, analyzerImpacts []deviceTrafficAnalyzerImpact, pcapImpact capture.PCAPSelectionImpact) ([]deviceTrafficChoiceImpact, bool) {
	eventsExact := events.Validate() == nil && events.QuerySnapshot.CountRelation == "eq"
	sessions := deviceTrafficSessions(pcapImpact)
	wholeEventsExact := len(wholeCaptureEvents) == len(sessions)
	var wholeEventRows int64
	for index, preview := range wholeCaptureEvents {
		wholeEventsExact = wholeEventsExact && index < len(sessions) && preview.Validate() == nil && preview.CaptureSessionID == sessions[index]
		wholeEventRows += preview.Database.EventRows
	}
	analyzersExact := len(analyzerImpacts) == len(sessions)
	checkpointCount := 0
	for index, impact := range analyzerImpacts {
		analyzersExact = analyzersExact && index < len(sessions) && impact.SessionID == sessions[index] && impact.Zeek.Validate() == nil && impact.Suricata.Validate() == nil && impact.Zeek.Engine == analyzer.EngineZeek && impact.Suricata.Engine == analyzer.EngineSuricata && impact.Zeek.CaptureSessionID == impact.SessionID && impact.Suricata.CaptureSessionID == impact.SessionID
		if impact.Zeek.CheckpointPresent {
			checkpointCount++
		}
		if impact.Suricata.CheckpointPresent {
			checkpointCount++
		}
	}
	pcapEligible := pcapImpact.Exact
	sanitizeCapacity := true
	retentionLocked := false
	var matched, collateral uint64
	var wholeBytes, sanitizedBytes int64
	var temporary uint64
	for _, impact := range pcapImpact.ImpactedFiles {
		matched += impact.MatchedPackets
		collateral += impact.CollateralPacketsInWholeDelete
		wholeBytes += impact.OriginalBytes
		sanitizedBytes += impact.OriginalBytes - impact.SanitizedBytes
		if impact.TemporaryBytesRequired > temporary {
			temporary = impact.TemporaryBytesRequired
		}
		sanitizeCapacity = sanitizeCapacity && impact.TemporaryCapacityAvailable
		retentionLocked = retentionLocked || impact.RetentionLocked
	}
	metadataEligible := eventsExact
	packetEligible := eventsExact && pcapEligible && !retentionLocked
	wholeEligible := packetEligible && wholeEventsExact && len(pcapImpact.ImpactedFiles) > 0
	collateralEventRows := wholeEventRows - events.Database.Database.EventRows
	if collateralEventRows < 0 {
		wholeEligible, collateralEventRows = false, 0
	}
	legacyChoices := []deviceTrafficChoiceImpact{
		{Choice: capture.DeleteMetadataOnly, Eligible: metadataEligible, ExecutionAvailable: metadataEligible, NormalizedEventRows: events.Database.Database.EventRows, RetainsPacketBytes: true, Warnings: []string{"Raw packet bytes remain in shared PCAP files."}},
		{Choice: capture.DeleteDerivedContentOnly, Eligible: false, RetainsPacketBytes: true, Warnings: []string{"Body, key-log, and search-index footprint backends are not yet coordinated; raw PCAP remains."}},
		{Choice: capture.DeleteWholeCaptureFiles, Eligible: wholeEligible, ExecutionAvailable: wholeEligible, NormalizedEventRows: wholeEventRows, CollateralEventRows: collateralEventRows, PCAPFilesDeleted: len(pcapImpact.ImpactedFiles), MatchedPacketsRemoved: matched, CollateralPacketsRemoved: collateral, PCAPBytesReclaimable: wholeBytes, RequiresReindex: false, Warnings: []string{"Deletes every unrelated retained packet in each impacted shared capture file.", "Because normalized events do not yet retain source-file provenance, all metadata for each affected capture session is deleted and permanently replay-blocked."}},
		{Choice: capture.SanitizeAndRewritePCAP, Eligible: packetEligible && sanitizeCapacity && len(pcapImpact.ImpactedFiles) > 0, ExecutionAvailable: packetEligible && sanitizeCapacity && len(pcapImpact.ImpactedFiles) > 0, NormalizedEventRows: events.Database.Database.EventRows, PCAPFilesRewritten: len(pcapImpact.ImpactedFiles), MatchedPacketsRemoved: matched, PCAPBytesReclaimable: sanitizedBytes, TemporaryBytesRequired: temporary, RequiresReindex: len(pcapImpact.ImpactedFiles) > 0, Warnings: []string{"Rewritten files require analyzer/search re-indexing; secure erasure is not guaranteed on SSD, COW, snapshots, backups, or prior exports."}},
	}
	if schema == legacyDeviceTrafficPreviewSchema {
		return legacyChoices, eventsExact && wholeEventsExact && pcapImpact.Exact
	}
	metadataEligible = metadataEligible && !retentionLocked
	derivedEligible := metadataEligible && pcapImpact.Exact && analyzersExact
	analyzerBarriers := len(analyzerImpacts) * 2
	choices := []deviceTrafficChoiceImpact{
		{Choice: capture.DeleteMetadataOnly, Eligible: metadataEligible, ExecutionAvailable: metadataEligible, NormalizedEventRows: events.Database.Database.EventRows, RetainsPacketBytes: true, Warnings: []string{"Raw packet bytes and analyzer checkpoints remain in shared capture sessions."}},
		{Choice: capture.DeleteDerivedContentOnly, Eligible: derivedEligible, ExecutionAvailable: derivedEligible, NormalizedEventRows: events.Database.Database.EventRows, AnalyzerCheckpointsRemoved: checkpointCount, AnalyzerReplayBarriers: analyzerBarriers, RetainsPacketBytes: true, Warnings: []string{"Removes selected normalized events and establishes session-wide Zeek and Suricata replay barriers while every raw PCAP byte remains.", "HTTP-body, TLS-key-log, Arkime, and OpenSearch stores are not configured in this build and contribute zero managed objects; existing exports and backups remain independent."}},
		{Choice: capture.DeleteWholeCaptureFiles, Eligible: wholeEligible, ExecutionAvailable: wholeEligible, NormalizedEventRows: wholeEventRows, CollateralEventRows: collateralEventRows, PCAPFilesDeleted: len(pcapImpact.ImpactedFiles), MatchedPacketsRemoved: matched, CollateralPacketsRemoved: collateral, PCAPBytesReclaimable: wholeBytes, AnalyzerCheckpointsRemoved: checkpointCount, AnalyzerReplayBarriers: analyzerBarriers, RequiresReindex: false, Warnings: []string{"Deletes every unrelated retained packet in each impacted shared capture file.", "Because normalized events do not yet retain source-file provenance, all metadata for each affected capture session is deleted and permanently replay-blocked."}},
		{Choice: capture.SanitizeAndRewritePCAP, Eligible: packetEligible && sanitizeCapacity && len(pcapImpact.ImpactedFiles) > 0, ExecutionAvailable: packetEligible && sanitizeCapacity && len(pcapImpact.ImpactedFiles) > 0, NormalizedEventRows: events.Database.Database.EventRows, PCAPFilesRewritten: len(pcapImpact.ImpactedFiles), MatchedPacketsRemoved: matched, PCAPBytesReclaimable: sanitizedBytes, TemporaryBytesRequired: temporary, AnalyzerCheckpointsRemoved: checkpointCount, AnalyzerReplayBarriers: analyzerBarriers, RequiresReindex: len(pcapImpact.ImpactedFiles) > 0, Warnings: []string{"Rewritten files require analyzer/search re-indexing; secure erasure is not guaranteed on SSD, COW, snapshots, backups, or prior exports."}},
	}
	return choices, eventsExact && wholeEventsExact && analyzersExact && pcapImpact.Exact
}

func eventSelectionFromPCAP(deviceID string, startAt, endAt time.Time, selection pcapng.SelectionRule) (ingest.EventSelection, error) {
	addresses := make([]ingest.EventSelectionAddress, 0, len(selection.Identities))
	for _, identity := range selection.Identities {
		if identity.Kind != pcapng.SelectionIdentityIP || identity.StartAt == nil || identity.EndAt == nil {
			continue
		}
		addresses = append(addresses, ingest.EventSelectionAddress{Address: identity.Value, StartAt: *identity.StartAt, EndAt: *identity.EndAt})
	}
	return ingest.CanonicalEventSelection(deviceID, startAt, endAt, addresses)
}

func hashDeviceTrafficPreview(preview deviceTrafficDeletionPreview) (string, error) {
	preview.PreviewSHA256 = ""
	encoded, err := json.Marshal(preview)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (p deviceTrafficDeletionPreview) validate() error {
	if p.Schema != legacyDeviceTrafficPreviewSchema && p.Schema != deviceTrafficPreviewSchema || !deviceinventory.ValidDeviceID(p.DeviceID) || p.StartAt.Location() != time.UTC || p.EndAt.Location() != time.UTC || !p.StartAt.Before(p.EndAt) || p.EndAt.Sub(p.StartAt) > maxDeviceTrafficRange || p.InventoryEvidenceAsOf.IsZero() || p.GeneratedAt.IsZero() || !p.ExpiresAt.After(p.GeneratedAt) || p.SecureErasureGuaranteed || p.Confirmation != p.DeviceID || len(p.CapabilityLimitations) > 8 || ingest.ValidateEventQuerySnapshot(p.NormalizedEvents) != nil || p.NormalizedEventDeletion.Validate() != nil || !reflect.DeepEqual(p.NormalizedEvents, p.NormalizedEventDeletion.QuerySnapshot) || p.NormalizedEventDeletion.Selection.DeviceID != p.DeviceID || !p.NormalizedEventDeletion.Selection.StartAt.Equal(p.StartAt) || !p.NormalizedEventDeletion.Selection.EndAt.Equal(p.EndAt) || p.PCAP.Validate() != nil || p.ExpiresAt.After(p.NormalizedEventDeletion.ExpiresAt) || p.GeneratedAt.Before(p.NormalizedEventDeletion.GeneratedAt) || p.ExistingExportRecords < 0 || p.ExistingExportRecords > maxCaptureExportRecords || len(p.Choices) != 4 || len(p.PreviewSHA256) != sha256.Size*2 {
		return errors.New("device traffic deletion preview is invalid")
	}
	if p.DeviceName != "" && (len(p.DeviceName) > 128 || p.DeviceName != strings.TrimSpace(p.DeviceName)) {
		return errors.New("device traffic deletion preview name is invalid")
	}
	for _, limitation := range p.CapabilityLimitations {
		if limitation == "" || len(limitation) > 256 || limitation != strings.TrimSpace(limitation) {
			return errors.New("device traffic deletion preview limitation is invalid")
		}
	}
	selection, err := eventSelectionFromPCAP(p.DeviceID, p.StartAt, p.EndAt, p.PCAP.Selection)
	if err != nil || !reflect.DeepEqual(selection, p.NormalizedEventDeletion.Selection) {
		return errors.New("device traffic deletion backend selections differ")
	}
	expectedSessions := deviceTrafficSessions(p.PCAP)
	if len(p.AnalyzerReindex) != len(expectedSessions) || len(p.WholeCaptureEvents) != len(expectedSessions) {
		return errors.New("device traffic deletion analyzer population is incomplete")
	}
	for index, impact := range p.AnalyzerReindex {
		wholeEvents := p.WholeCaptureEvents[index]
		if impact.SessionID != expectedSessions[index] || wholeEvents.Validate() != nil || wholeEvents.CaptureSessionID != expectedSessions[index] || p.ExpiresAt.After(wholeEvents.ExpiresAt) || impact.Zeek.Validate() != nil || impact.Suricata.Validate() != nil || impact.Zeek.Engine != analyzer.EngineZeek || impact.Suricata.Engine != analyzer.EngineSuricata || impact.Zeek.CaptureSessionID != impact.SessionID || impact.Suricata.CaptureSessionID != impact.SessionID || p.ExpiresAt.After(impact.Zeek.ExpiresAt) || p.ExpiresAt.After(impact.Suricata.ExpiresAt) {
			return errors.New("device traffic deletion analyzer evidence is invalid")
		}
	}
	if validateDeletionCopyBoundaries(p.CopyBoundaries, p.ExistingExportRecords) != nil {
		return errors.New("device traffic deletion copy boundaries are invalid")
	}
	expectedChoices, exact := buildDeviceTrafficChoicesForSchema(p.Schema, p.NormalizedEventDeletion, p.WholeCaptureEvents, p.AnalyzerReindex, p.PCAP)
	if exact != p.ExactImpact || !reflect.DeepEqual(expectedChoices, p.Choices) {
		return errors.New("device traffic deletion choices do not match backend evidence")
	}
	expected, err := hashDeviceTrafficPreview(p)
	if err != nil || expected != p.PreviewSHA256 {
		return errors.New("device traffic deletion preview digest does not match")
	}
	return nil
}

func selectionDigest(selection pcapng.SelectionRule) string {
	encoded, _ := json.Marshal(selection)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func compactServerStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
