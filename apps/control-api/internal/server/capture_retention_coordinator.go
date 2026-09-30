package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayclient"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func (s *Server) coordinateCaptureRetentionRun(ctx context.Context, run capture.RetentionRun) (capture.RetentionRun, error) {
	s.captureRetentionMu.Lock()
	defer s.captureRetentionMu.Unlock()
	if run.State == capture.RetentionRunCompleted || run.State == capture.RetentionRunPartial || run.State == capture.RetentionRunFailed {
		return run, nil
	}
	for _, item := range run.Items {
		if item.State != capture.RetentionItemPending {
			continue
		}
		operationKey, err := retentionCoordinationKey(run.ID, item.SessionID)
		if err != nil {
			return run, err
		}
		record, err := s.store.getCoordinatedCaptureDeletionByIdempotencyKey(operationKey)
		if errors.Is(err, os.ErrNotExist) {
			record, err = s.beginRetentionCaptureDeletion(ctx, run, item, operationKey)
		}
		if err != nil {
			return run, err
		}
		if record.Job.SessionID != item.SessionID || record.Job.Administrator != run.Administrator {
			return run, errors.New("capture retention coordinated deletion evidence is inconsistent")
		}
		if record.Job.State != coordinatedDeletionCompleted && record.Job.State != coordinatedDeletionFailed && record.Job.State != coordinatedDeletionPartial {
			s.captureDeletionMu.Lock()
			record.Job, err = s.executeCoordinatedCaptureDeletion(ctx, record)
			s.captureDeletionMu.Unlock()
			if err != nil {
				return run, err
			}
		}
		outcome := capture.RecordRetentionItemOutcomeRequest{RunID: run.ID, SessionID: item.SessionID, State: capture.RetentionItemFailed, CoordinatedDeletionJobID: record.Job.ID, Failure: retentionDeletionFailure(record.Job)}
		if record.Job.State == coordinatedDeletionCompleted {
			host := record.Job.Backends[len(record.Job.Backends)-1].HostArtifacts
			if host == nil || host.State != capture.DeletionCompleted {
				return run, errors.New("capture retention coordinated deletion lacks host acknowledgement")
			}
			outcome.State, outcome.DeletionJobID, outcome.Failure = capture.RetentionItemDeleted, host.ID, ""
		}
		if err := s.gateway.Call(ctx, "RecordCaptureRetentionItemOutcome", gatewayprotocol.RecordCaptureRetentionItemOutcomeParams{Request: outcome}, &run); err != nil {
			return run, err
		}
		if !retentionOutcomeAcknowledged(run, outcome) {
			return run, errors.New("capture retention host returned inconsistent outcome evidence")
		}
	}
	return run, nil
}

func (s *Server) beginRetentionCaptureDeletion(ctx context.Context, run capture.RetentionRun, item capture.RetentionRunItem, operationKey string) (coordinatedCaptureDeletionRecord, error) {
	if s.captureEventDeletions == nil || s.zeekCheckpointDeletions == nil || s.suricataCheckpointDeletions == nil {
		return coordinatedCaptureDeletionRecord{}, errors.New("capture deletion services are not configured")
	}
	if run.Trigger == capture.RetentionTriggerManual {
		reviewed, err := s.store.getCoordinatedCaptureRetentionPreviewByHostDigest(run.PreviewSHA256, run.Administrator)
		if err != nil {
			return coordinatedCaptureDeletionRecord{}, fmt.Errorf("load reviewed capture retention preview: %w", err)
		}
		preview, err := retentionSelectedPreview(reviewed.Preview, item.SessionID)
		if err != nil || preview.HostArtifacts.PreviewSHA256 != item.DeletionPreviewSHA256 || !preview.HostArtifacts.ExpiresAt.Equal(item.DeletionPreviewExpiresAt) || preview.HostArtifacts.Footprint != item.Footprint {
			return coordinatedCaptureDeletionRecord{}, errors.New("capture retention item does not match the reviewed backend preview")
		}
		s.captureDeletionMu.Lock()
		defer s.captureDeletionMu.Unlock()
		record, _, err := s.store.beginCoordinatedCaptureDeletion(preview, run.Administrator, operationKey)
		return record, err
	}
	var hostPreview capture.DeletionPreview
	if err := s.gateway.Call(ctx, "PreviewCaptureDeletionUntil", gatewayprotocol.PreviewCaptureDeletionUntilParams{SessionID: item.SessionID, ExpiresAt: item.DeletionPreviewExpiresAt}, &hostPreview); err != nil {
		return coordinatedCaptureDeletionRecord{}, err
	}
	if hostPreview.PreviewSHA256 != item.DeletionPreviewSHA256 || hostPreview.Footprint != item.Footprint {
		return coordinatedCaptureDeletionRecord{}, errors.New("capture retention host preview drifted from the durable plan")
	}
	eventPreview, err := s.captureEventDeletions.Preview(ctx, item.SessionID)
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, err
	}
	zeekPreview, err := s.zeekCheckpointDeletions.Preview(ctx, item.SessionID)
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, err
	}
	suricataPreview, err := s.suricataCheckpointDeletions.Preview(ctx, item.SessionID)
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, err
	}
	exports, err := s.store.ListCaptureExports(item.SessionID)
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, err
	}
	preview, err := newCoordinatedCaptureDeletionPreview(hostPreview, eventPreview, zeekPreview, suricataPreview, len(exports))
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, err
	}
	s.captureDeletionMu.Lock()
	defer s.captureDeletionMu.Unlock()
	record, _, err := s.store.beginCoordinatedCaptureDeletion(preview, run.Administrator, operationKey)
	return record, err
}

func (s *Server) ResumeCaptureRetentionRuns(ctx context.Context) error {
	var runs []capture.RetentionRun
	if err := s.gateway.Call(ctx, "ListCaptureRetentionRuns", gatewayprotocol.EmptyParams{}, &runs); err != nil {
		return err
	}
	for _, run := range runs {
		if run.State != capture.RetentionRunPending && run.State != capture.RetentionRunRunning {
			continue
		}
		if _, err := s.coordinateCaptureRetentionRun(ctx, run); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) RunCaptureRetentionScheduler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	run := func() {
		err := s.RunCaptureRetentionSchedulerOnce(ctx)
		if ctx.Err() == nil {
			s.reportCaptureRetentionSchedulerResult(err)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

// reportCaptureRetentionSchedulerResult logs scheduler state changes instead
// of every 30-second tick. A daemon profile without packet capture (such as
// development) is reported once at info level; repeated identical failures
// are logged once until the scheduler recovers or the failure changes.
func (s *Server) reportCaptureRetentionSchedulerResult(err error) {
	const captureUnavailable = "capture-unavailable"
	s.retentionSchedulerMu.Lock()
	defer s.retentionSchedulerMu.Unlock()
	previous := s.retentionSchedulerLastError
	var remote *gatewayclient.RemoteError
	switch {
	case err == nil:
		if previous != "" && previous != captureUnavailable {
			s.logger.Info("capture retention scheduler recovered")
		}
		s.retentionSchedulerLastError = ""
	case errors.As(err, &remote) && remote.Code == gatewayclient.CodeCaptureUnavailable:
		if previous != captureUnavailable {
			s.logger.Info("capture retention scheduler idle: packet capture is not available in this daemon profile")
		}
		s.retentionSchedulerLastError = captureUnavailable
	default:
		if err.Error() != previous {
			s.logger.Error("capture retention scheduler check failed; further identical failures are suppressed until it recovers", "error", err)
		}
		s.retentionSchedulerLastError = err.Error()
	}
}

func (s *Server) RunCaptureRetentionSchedulerOnce(ctx context.Context) error {
	if err := s.ResumeCaptureRetentionRuns(ctx); err != nil {
		return fmt.Errorf("resume capture retention runs: %w", err)
	}
	var tick capture.RetentionSchedulerTick
	if err := s.gateway.Call(ctx, "RunCaptureRetentionSchedulerOnce", gatewayprotocol.EmptyParams{}, &tick); err != nil {
		return err
	}
	if tick.Run == nil {
		return nil
	}
	coordinated, err := s.coordinateCaptureRetentionRun(ctx, *tick.Run)
	if err != nil {
		return fmt.Errorf("coordinate automatic capture retention run %s: %w", tick.Run.ID, err)
	}
	s.logger.Info("automatic capture retention run completed", "run_id", coordinated.ID, "state", coordinated.State, "deleted", coordinated.DeletedSessions, "failed", coordinated.FailedSessions)
	return nil
}

func retentionCoordinationKey(runID, sessionID string) (string, error) {
	digest, err := coordinatorHashJSON(struct {
		RunID     string `json:"run_id"`
		SessionID string `json:"session_id"`
	}{runID, sessionID})
	if err != nil {
		return "", err
	}
	return "retention-coordinate-" + digest[:32], nil
}

func retentionDeletionFailure(job coordinatedCaptureDeletionJob) string {
	if job.Failure != "" {
		return boundedCoordinatorFailure(errors.New(job.Failure))
	}
	return fmt.Sprintf("coordinated capture deletion ended %s", job.State)
}

func retentionOutcomeAcknowledged(run capture.RetentionRun, outcome capture.RecordRetentionItemOutcomeRequest) bool {
	if run.ID != outcome.RunID {
		return false
	}
	for _, item := range run.Items {
		if item.SessionID == outcome.SessionID {
			return item.State == outcome.State && item.CoordinatedDeletionJobID == outcome.CoordinatedDeletionJobID && item.DeletionJobID == outcome.DeletionJobID && item.Failure == outcome.Failure
		}
	}
	return false
}
