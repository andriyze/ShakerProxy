package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/casework"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

type createCaseRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Reason      string `json:"reason"`
}
type addCaseEvidenceRequest struct {
	ExpectedRevision uint64                `json:"expected_revision"`
	Kind             casework.EvidenceKind `json:"kind"`
	ArtifactID       string                `json:"artifact_id"`
	Label            string                `json:"label"`
	Reason           string                `json:"reason"`
}
type setCaseStatusRequest struct {
	ExpectedRevision uint64          `json:"expected_revision"`
	Status           casework.Status `json:"status"`
	Reason           string          `json:"reason"`
	Password         string          `json:"password"`
}
type setCaseHoldRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Active           bool   `json:"active"`
	Reason           string `json:"reason"`
	Password         string `json:"password"`
}

func (s *Server) listCases(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "case list does not accept query parameters")
		return
	}
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	items, err := s.cases.List()
	if err != nil {
		s.logger.Warn("list cases failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "cases are temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "cases": items})
}

func (s *Server) createCase(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	var request createCaseRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "case")
		return
	}
	if strings.TrimSpace(request.Reason) == "" {
		request.Reason = "Case created"
	}
	item, err := s.cases.Create(strings.TrimSpace(request.Name), request.Description, sessionUsername(r.Context()), strings.TrimSpace(request.Reason))
	if err != nil {
		s.writeCaseError(w, err, http.StatusUnprocessableEntity, "case_rejected")
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "case detail does not accept query parameters")
		return
	}
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	item, err := s.cases.Get(r.PathValue("caseID"))
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "case_not_found", "case was not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) addCaseEvidence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	var request addCaseEvidenceRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "case evidence")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	input, err := s.validateCaseEvidence(ctx, sessionUsername(r.Context()), request.Kind, request.ArtifactID)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "evidence_unavailable", err.Error())
		return
	}
	input.Label = strings.TrimSpace(request.Label)
	if input.Label == "" {
		input.Label = defaultEvidenceLabel(input)
	}
	reason := strings.TrimSpace(request.Reason)
	if reason == "" {
		reason = "Evidence added"
	}
	item, err := s.cases.AttachEvidence(r.PathValue("caseID"), request.ExpectedRevision, input, sessionUsername(r.Context()), reason)
	if err != nil {
		s.writeCaseError(w, err, http.StatusConflict, "case_evidence_rejected")
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

// validateCaseEvidence confirms the artifact exists and, for a query
// snapshot, pins its canonical query and dataset watermark so the evidence
// remains meaningful after the snapshot itself expires.
func (s *Server) validateCaseEvidence(ctx context.Context, actor string, kind casework.EvidenceKind, id string) (casework.EvidenceInput, error) {
	input := casework.EvidenceInput{Kind: kind, ArtifactID: id}
	switch kind {
	case casework.EvidenceCapture:
		var view capture.View
		if err := s.gateway.Call(ctx, "GetCaptureStats", gatewayprotocol.GetCaptureStatsParams{SessionID: id}, &view); err != nil {
			return input, errors.New("The capture was not found or capture status is unavailable; list captures with GET /api/v1/captures.")
		}
		return input, nil
	case casework.EvidenceCaptureExport:
		records, err := s.store.ListCaptureExports("")
		if err != nil {
			return input, errors.New("The capture export history is unavailable; try again.")
		}
		for _, record := range records {
			if record.ID == id && record.Complete {
				return input, nil
			}
		}
		return input, errors.New("No completed capture export has this ID; see GET /api/v1/captures/{id}/exports.")
	case casework.EvidenceQuerySnapshot:
		if s.eventSnapshots == nil {
			return input, errors.New("Event query snapshots are not configured on this appliance.")
		}
		snapshot, err := s.eventSnapshots.GetEventQuerySnapshot(ctx, actor, id)
		if err != nil {
			return input, errors.New("The query snapshot was not found or has expired; freeze the query again with POST /api/v1/event-query-snapshots and attach the new ID.")
		}
		var anchor *time.Time
		if snapshot.QueryAnchor != nil {
			value := snapshot.QueryAnchor.UTC()
			anchor = &value
		}
		input.Query = &casework.QuerySnapshotPin{
			CanonicalQuery: snapshot.CanonicalQuery, QueryAnchor: anchor, MatchedCount: snapshot.MatchedCount,
			CountRelation: snapshot.CountRelation, SnapshotCreatedAt: snapshot.CreatedAt.UTC(), SnapshotSHA256: snapshot.SnapshotSHA256,
			DatasetWatermark: casework.QueryWatermark{IngestSequence: snapshot.DatasetWatermark.IngestSequence, ReceivedAt: snapshot.DatasetWatermark.ReceivedAt.UTC(), RecordID: snapshot.DatasetWatermark.RecordID},
		}
		return input, nil
	default:
		return input, errors.New("kind must be CAPTURE, CAPTURE_EXPORT or QUERY_SNAPSHOT.")
	}
}

func defaultEvidenceLabel(input casework.EvidenceInput) string {
	switch input.Kind {
	case casework.EvidenceCapture:
		return "Capture " + input.ArtifactID
	case casework.EvidenceCaptureExport:
		return "Capture export " + input.ArtifactID
	case casework.EvidenceQuerySnapshot:
		label := "Traffic query"
		if input.Query != nil && input.Query.CanonicalQuery != "" {
			label = "Traffic query: " + input.Query.CanonicalQuery
		}
		if len(label) > 256 {
			label = strings.TrimSpace(label[:253]) + "..."
		}
		return label
	default:
		return string(input.Kind)
	}
}

// writeCaseError maps casework errors to actionable HTTP responses.
func (s *Server) writeCaseError(w http.ResponseWriter, err error, rejectedStatus int, rejectedCode string) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		writeError(w, http.StatusNotFound, "case_not_found", "The case or evidence was not found; list cases with GET /api/v1/cases.")
	case errors.Is(err, casework.ErrRevisionChanged):
		writeError(w, http.StatusConflict, "case_revision_changed", "The case changed since it was loaded; reload it and try again.")
	case errors.Is(err, casework.ErrHoldActive):
		writeError(w, http.StatusConflict, "case_hold_active", "The case evidence hold is active: "+strings.TrimPrefix(err.Error(), casework.ErrHoldActive.Error()+": ")+".")
	case errors.Is(err, casework.ErrCaseLimit):
		writeError(w, http.StatusConflict, "case_limit", "Case limit reached: "+strings.TrimPrefix(err.Error(), casework.ErrCaseLimit.Error()+": ")+".")
	default:
		writeError(w, rejectedStatus, rejectedCode, err.Error())
	}
}

type updateCaseRequest struct {
	ExpectedRevision uint64  `json:"expected_revision"`
	Name             *string `json:"name,omitempty"`
	Description      *string `json:"description,omitempty"`
	Reason           string  `json:"reason"`
}

// updateCase renames a case or edits its (multi-line) description.
func (s *Server) updateCase(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	var request updateCaseRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "case update")
		return
	}
	if request.Name == nil && request.Description == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Include name, description, or both.")
		return
	}
	item, changed, err := s.cases.Update(r.PathValue("caseID"), request.ExpectedRevision, casework.Update{Name: request.Name, Description: request.Description}, sessionUsername(r.Context()), request.Reason)
	if err != nil {
		s.writeCaseError(w, err, http.StatusUnprocessableEntity, "case_update_rejected")
		return
	}
	if changed {
		s.logger.Info("case updated", "username", sessionUsername(r.Context()), "case_id", item.ID, "revision", item.Revision)
	}
	writeJSON(w, http.StatusOK, item)
}

type removeCaseEvidenceRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
}

// removeCaseEvidence detaches evidence; the artifact itself is kept.
func (s *Server) removeCaseEvidence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	var request removeCaseEvidenceRequest
	if err := decodeOptionalJSON(r, &request, 8<<10); err != nil {
		writeDecodeError(w, err, "case evidence removal")
		return
	}
	item, err := s.cases.RemoveEvidence(r.PathValue("caseID"), r.PathValue("evidenceID"), request.ExpectedRevision, sessionUsername(r.Context()), request.Reason)
	if err != nil {
		s.writeCaseError(w, err, http.StatusConflict, "case_evidence_rejected")
		return
	}
	s.logger.Info("case evidence removed", "username", sessionUsername(r.Context()), "case_id", item.ID, "evidence_id", r.PathValue("evidenceID"))
	writeJSON(w, http.StatusOK, item)
}

type deleteCaseRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Password         string `json:"password"`
}

// deleteCase removes a case record (not its evidence artifacts) once no
// capture is held for it.
func (s *Server) deleteCase(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	var request deleteCaseRequest
	if err := decodeOptionalJSON(r, &request, 4<<10); err != nil {
		writeDecodeError(w, err, "case deletion")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	deleted, err := s.cases.Delete(r.PathValue("caseID"), request.ExpectedRevision)
	if err != nil {
		s.writeCaseError(w, err, http.StatusConflict, "case_delete_rejected")
		return
	}
	s.logger.Info("case deleted", "username", sessionUsername(r.Context()), "case_id", deleted.ID, "name", deleted.Name, "evidence", len(deleted.Evidence))
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "deleted": true, "case": deleted})
}

func (s *Server) setCaseStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	var request setCaseStatusRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "case status")
		return
	}
	if strings.TrimSpace(request.Reason) == "" {
		request.Reason = "Case " + strings.ToLower(string(request.Status))
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	item, err := s.cases.SetStatus(r.PathValue("caseID"), request.ExpectedRevision, request.Status, sessionUsername(r.Context()), strings.TrimSpace(request.Reason))
	if err != nil {
		s.writeCaseError(w, err, http.StatusConflict, "case_status_rejected")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) setCaseHold(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	idempotency, validKey := requestOperationID(r, validCaseOperationKey)
	if !validKey {
		writeError(w, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must be 16-128 printable characters; omit the header to let the server generate one.")
		return
	}
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	var request setCaseHoldRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "case hold")
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Reason == "" {
		request.Reason = "Evidence hold released"
		if request.Active {
			request.Reason = "Evidence hold applied"
		}
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	item, err := s.cases.Get(r.PathValue("caseID"))
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "case_not_found", "case was not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case is temporarily unavailable")
		return
	}
	actor := sessionUsername(r.Context())
	if item.Hold.OperationID == idempotency && item.Hold.DesiredActive == request.Active && item.Hold.Reason == request.Reason && item.Hold.Actor == actor {
		writeJSON(w, http.StatusOK, item)
		return
	}
	if request.ExpectedRevision != 0 && item.Revision != request.ExpectedRevision {
		writeError(w, http.StatusConflict, "case_revision_changed", "The case changed since it was loaded; reload it and try again.")
		return
	}
	results := make([]casework.HoldResult, 0)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	for _, evidence := range item.Evidence {
		if evidence.Kind != casework.EvidenceCapture {
			continue
		}
		result := casework.HoldResult{EvidenceID: evidence.ID, ArtifactID: evidence.ArtifactID}
		var view capture.View
		if err := s.gateway.Call(ctx, "GetCaptureStats", gatewayprotocol.GetCaptureStatsParams{SessionID: evidence.ArtifactID}, &view); err != nil {
			result.Failure = "capture host state unavailable"
			results = append(results, result)
			continue
		}
		currentRevision := uint64(0)
		currentActive := false
		currentCase := ""
		if view.EvidenceHold != nil {
			currentRevision = view.EvidenceHold.Revision
			currentActive = view.EvidenceHold.Active
			currentCase = view.EvidenceHold.CaseID
		}
		if request.Active && currentActive && currentCase == item.ID {
			result.Protected = true
			result.Revision = currentRevision
			results = append(results, result)
			continue
		}
		if !request.Active && !currentActive {
			result.Protected = false
			result.Revision = currentRevision
			results = append(results, result)
			continue
		}
		holdRequest := capture.SetHoldRequest{SessionID: evidence.ArtifactID, CaseID: item.ID, Active: request.Active, ExpectedRevision: currentRevision, Actor: actor, Reason: request.Reason, IdempotencyKey: caseHoldArtifactKey(idempotency, evidence.ID)}
		var hold capture.EvidenceHold
		if err := s.gateway.Call(ctx, "SetCaptureEvidenceHold", gatewayprotocol.SetCaptureEvidenceHoldParams{Request: holdRequest}, &hold); err != nil {
			result.Failure = "capture hold mutation failed"
		} else if hold.SessionID != evidence.ArtifactID || hold.Revision == 0 || hold.Active != request.Active || (hold.Active && hold.CaseID != item.ID) || (!hold.Active && hold.CaseID != "") {
			result.Failure = "capture hold acknowledgement was invalid"
		} else {
			result.Protected = hold.Active
			result.Revision = hold.Revision
		}
		results = append(results, result)
	}
	updated, err := s.cases.RecordHold(item.ID, item.Revision, request.Active, request.Reason, actor, idempotency, results)
	if err != nil {
		if errors.Is(err, casework.ErrRevisionChanged) {
			s.writeCaseError(w, err, http.StatusConflict, "case_hold_record_failed")
			return
		}
		writeError(w, http.StatusConflict, "case_hold_record_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func caseHoldArtifactKey(operationID, evidenceID string) string {
	sum := sha256.Sum256([]byte(operationID + "\x00" + evidenceID))
	return "casehold-" + hex.EncodeToString(sum[:16])
}

func validCaseOperationKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
