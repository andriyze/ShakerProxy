package server

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
)

type captureDeletionAnalyzerStub struct {
	engine          analyzer.Engine
	health          *analyzer.HealthSnapshot
	statusErr       error
	preview         *analyzer.CheckpointDeletionPreview
	previewErr      error
	deleteErr       error
	reindexErr      error
	reindexState    string
	deleteRequests  []analyzer.CheckpointDeletionRequest
	reindexRequests []analyzer.CheckpointReindexRequest
}

func (s *captureDeletionAnalyzerStub) Status(_ context.Context) (analyzer.HealthSnapshot, error) {
	if s.statusErr != nil {
		return analyzer.HealthSnapshot{}, s.statusErr
	}
	if s.health == nil {
		return analyzer.HealthSnapshot{}, errors.New("status unavailable")
	}
	return *s.health, nil
}

func (s *captureDeletionAnalyzerStub) AuthorizeReindex(_ context.Context, request analyzer.CheckpointReindexRequest) (analyzer.CheckpointReindexOutcome, error) {
	s.reindexRequests = append(s.reindexRequests, request)
	if s.reindexErr != nil {
		return analyzer.CheckpointReindexOutcome{}, s.reindexErr
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	state := s.reindexState
	if state == "" {
		state = "AUTHORIZED"
	}
	outcome := analyzer.CheckpointReindexOutcome{
		Schema: analyzer.CheckpointReindexSchema, OperationID: request.OperationID, Actor: request.Actor,
		Engine: s.engine, CaptureSessionID: request.CaptureSessionID, DeletionOperationID: request.DeletionOperationID,
		DeletionPreviewSHA256: request.DeletionPreviewSHA256, TargetManifestSHA256: request.TargetManifestSHA256,
		State: state, AuthorizedAt: now,
	}
	if state == "COMPLETED" {
		outcome.CompletedAt = &now
	}
	return outcome, nil
}

func (s *captureDeletionAnalyzerStub) Preview(_ context.Context, sessionID string) (analyzer.CheckpointDeletionPreview, error) {
	if s.previewErr != nil {
		return analyzer.CheckpointDeletionPreview{}, s.previewErr
	}
	if s.preview == nil || s.preview.Engine != s.engine || s.preview.CaptureSessionID != sessionID {
		return analyzer.CheckpointDeletionPreview{}, errors.New("unexpected analyzer checkpoint preview scope")
	}
	return *s.preview, nil
}

func (s *captureDeletionAnalyzerStub) Delete(_ context.Context, request analyzer.CheckpointDeletionRequest) (analyzer.CheckpointDeletionOutcome, error) {
	s.deleteRequests = append(s.deleteRequests, request)
	if s.deleteErr != nil {
		return analyzer.CheckpointDeletionOutcome{}, s.deleteErr
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return analyzer.CheckpointDeletionOutcome{
		Schema: analyzer.CheckpointDeletionSchema, Engine: s.engine, CaptureSessionID: request.Preview.CaptureSessionID,
		OperationID: request.OperationID, Actor: request.Actor, PreviewSHA256: request.Preview.PreviewSHA256,
		CheckpointWasPresent: request.Preview.CheckpointPresent, DeletedCheckpointBytes: request.Preview.CheckpointBytes,
		ActiveProgressWasPresent: request.Preview.ActiveProgressPresent, DeletedActiveProgressBytes: request.Preview.ActiveProgressBytes,
		VerifiedAbsent: true, CreatedAt: now, CompletedAt: now,
	}, nil
}

func configureAnalyzerDeletionPreviews(config *Config, preview coordinatedCaptureDeletionPreview) (*captureDeletionAnalyzerStub, *captureDeletionAnalyzerStub) {
	zeek := &captureDeletionAnalyzerStub{engine: analyzer.EngineZeek, preview: preview.ZeekCheckpoint}
	suricata := &captureDeletionAnalyzerStub{engine: analyzer.EngineSuricata, preview: preview.SuricataCheckpoint}
	config.ZeekCheckpointDeletions = zeek
	config.SuricataCheckpointDeletions = suricata
	return zeek, suricata
}

func analyzerDeletionPreviewForSession(t *testing.T, engine analyzer.Engine, sessionID string, now time.Time) analyzer.CheckpointDeletionPreview {
	t.Helper()
	service, err := analyzer.NewCheckpointDeletionService(analyzer.NewStateStore(filepath.Join(t.TempDir(), string(engine))), engine)
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now }
	preview, err := service.Preview(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return preview
}
