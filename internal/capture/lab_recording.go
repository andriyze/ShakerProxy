package capture

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The lab recording is the capture gatewayd keeps running while a confirmed
// lab plan routes, so testers never have to remember to start one. It is an
// ordinary full-packet ring (DefaultMaxFiles x DefaultSegmentSizeMiB, so at
// most 512 MiB on disk) that gatewayd restarts every day, after a reboot and
// whenever the lab plan changes. Only LabRecordingKeep finished recordings
// are kept, so automatic recording never holds more than
// (LabRecordingKeep+1) x 512 MiB. Recordings under an evidence hold are kept
// until the hold is released.
const (
	LabRecordingName          = "Lab traffic"
	LabRecordingAdministrator = "ShakerProxy"
	LabRecordingDuration      = 24 * time.Hour
	LabRecordingKeep          = 2
	labRecordingDescription   = "Recorded automatically while the lab routes. A manual capture replaces it until the manual capture ends."
	labRecordingStartReason   = "automatic lab recording"
	labRecordingInterrupted   = "interrupted before it finished (host restart)"
)

// LabRecordingRequest is the start request for one automatic lab recording.
// Every call gets a fresh idempotency key: an earlier recording must never be
// returned in place of a new one.
func LabRecordingRequest(planHash string) StartRequest {
	scope := strings.ToLower(planHash)
	if len(scope) > 16 {
		scope = scope[:16]
	}
	return StartRequest{
		Name: LabRecordingName, Description: labRecordingDescription, Mode: ModeFull,
		StopAfterSeconds: int(LabRecordingDuration / time.Second),
		Administrator:    LabRecordingAdministrator, StartReason: labRecordingStartReason,
		IdempotencyKey: "lab-recording-" + scope + "-" + rand.Text(),
		Automatic:      true,
	}
}

// LabRecordingDiskBound is the most PCAP automatic recording can keep: the
// running ring plus LabRecordingKeep finished ones.
func LabRecordingDiskBound() uint64 {
	request := LabRecordingRequest("").WithDefaults()
	return uint64(LabRecordingKeep+1) * uint64(request.SegmentSizeMiB) * uint64(request.MaxFiles) << 20
}

// TidyLabRecordings finalizes automatic recordings a host restart cut off
// (so they can be listed, exported and deleted like any other capture) and
// deletes all but the newest keep finished ones. Manual captures are never
// touched. It returns every problem it met; one recording failing does not
// stop the rest.
func (m *Manager) TidyLabRecordings(ctx context.Context, keep int) error {
	views, err := m.List(ctx)
	if err != nil {
		return err
	}
	var problems []error
	finished := make([]View, 0, len(views))
	for _, view := range views {
		if !view.Session.Request.Automatic || view.Active {
			continue
		}
		if view.Manifest == nil {
			if err := m.finalizeInterrupted(view); err != nil {
				problems = append(problems, fmt.Errorf("finalize %s: %w", view.Session.ID, err))
				continue
			}
		}
		finished = append(finished, view)
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].Session.StartedAt.After(finished[j].Session.StartedAt) })
	for index, view := range finished {
		if index < keep {
			continue
		}
		if err := m.deleteLabRecording(ctx, view.Session.ID); err != nil {
			problems = append(problems, fmt.Errorf("delete %s: %w", view.Session.ID, err))
		}
	}
	return errors.Join(problems...)
}

// finalizeInterrupted closes a recording whose worker never wrote its final
// state, as after a power loss or reboot.
func (m *Manager) finalizeInterrupted(view View) error {
	now := m.now()
	status := WorkerStatus{Schema: SchemaVersion, SessionID: view.Session.ID, State: StateStopped, StartedAt: view.Session.StartedAt, EndedAt: now, UpdatedAt: now, StopReason: labRecordingInterrupted}
	if view.Worker != nil {
		status = *view.Worker
		switch status.State {
		case StateStarting, StateRunning:
			status.State, status.StopReason = StateStopped, labRecordingInterrupted
			status.EndedAt, status.UpdatedAt = now, now
		}
	}
	if err := m.Store.WriteWorkerStatus(status); err != nil {
		return err
	}
	manifest, err := m.Store.CollectFiles(view.Session.ID, now)
	if err != nil {
		return err
	}
	return m.Store.WriteManifest(manifest)
}

func (m *Manager) deleteLabRecording(ctx context.Context, id string) error {
	preview, err := m.PreviewDeletion(ctx, id)
	if err != nil {
		return err
	}
	if preview.RetentionLock {
		return nil // an evidence hold keeps it until released
	}
	_, err = m.Delete(ctx, DeleteRequest{
		SessionID: id, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt,
		Confirmation: id, Administrator: LabRecordingAdministrator,
		IdempotencyKey: "lab-recording-prune-" + strings.TrimPrefix(id, "capture-"),
	})
	return err
}
