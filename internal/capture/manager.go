package capture

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Controller interface {
	Start(context.Context, string) error
	Stop(context.Context, string) error
	Active(context.Context, string) (bool, error)
}

type Manager struct {
	Store           Store
	Controller      Controller
	SoftwareVersion string
	Now             func() time.Time
	Random          func([]byte) (int, error)
	deletionMu      sync.Mutex
	retentionMu     sync.Mutex
	retentionRunMu  sync.Mutex
}

func (m *Manager) Start(ctx context.Context, request StartRequest, source Source, operatingMode, policyRevision string) (View, error) {
	if m.Controller == nil {
		return View{}, errors.New("capture service controller is required")
	}
	request = request.WithDefaults()
	if err := request.Validate(); err != nil {
		return View{}, err
	}
	if err := source.Validate(); err != nil {
		return View{}, err
	}
	views, err := m.List(ctx)
	if err != nil {
		return View{}, err
	}
	var active *View
	for index, view := range views {
		if view.Session.Request.IdempotencyKey == request.IdempotencyKey {
			if view.Session.Request == request && view.Session.Source == source {
				return view, nil
			}
			return View{}, errors.New("capture idempotency key conflicts with an existing request")
		}
		if view.Active && active == nil {
			active = &views[index]
		}
	}
	if active != nil {
		// One capture runs at a time, so disk use stays one ring. A manual
		// capture takes over from the automatic lab recording, which gatewayd
		// resumes when the manual capture ends.
		if !active.Session.Request.Automatic || request.Automatic {
			return View{}, errors.New("another capture session is active")
		}
		if err := m.Controller.Stop(ctx, active.Session.ID); err != nil {
			return View{}, fmt.Errorf("stop the automatic lab recording: %w", err)
		}
	}
	available, err := m.Store.AvailableBytes()
	if err != nil {
		return View{}, fmt.Errorf("inspect capture storage: %w", err)
	}
	quota := uint64(request.SegmentSizeMiB) * uint64(request.MaxFiles) << 20
	if available <= DefaultReserveBytes+quota {
		return View{}, errors.New("capture storage cannot preserve the emergency reserve and requested ring quota")
	}
	random := m.Random
	if random == nil {
		random = rand.Read
	}
	idBytes := make([]byte, 16)
	if _, err := random(idBytes); err != nil {
		return View{}, errors.New("generate capture session ID")
	}
	now := m.now()
	session := Session{
		Schema: SchemaVersion, ID: fmt.Sprintf("capture-%x", idBytes), Request: request, Source: source,
		OperatingMode: operatingMode, PolicyRevision: policyRevision, SoftwareVersion: m.SoftwareVersion,
		StartedAt: now, StopAt: now.Add(time.Duration(request.StopAfterSeconds) * time.Second),
		ReserveBytes: DefaultReserveBytes, OutputBaseName: "capture.pcapng", DumpcapExecutable: "/usr/bin/dumpcap",
	}
	if err := m.Store.Create(session); err != nil {
		return View{}, err
	}
	if err := m.Controller.Start(ctx, session.ID); err != nil {
		status := WorkerStatus{Schema: SchemaVersion, SessionID: session.ID, State: StateFailed, UpdatedAt: m.now(), EndedAt: m.now(), Failure: "capture worker failed to start"}
		_ = m.Store.WriteWorkerStatus(status)
		return View{}, fmt.Errorf("start capture worker: %w", err)
	}
	return m.Get(ctx, session.ID)
}

func (m *Manager) Stop(ctx context.Context, id string) (View, error) {
	if !ValidSessionID(id) {
		return View{}, errors.New("invalid capture session ID")
	}
	if m.Controller == nil {
		return View{}, errors.New("capture service controller is required")
	}
	if _, err := m.Store.ReadSession(id); err != nil {
		return View{}, err
	}
	active, err := m.Controller.Active(ctx, id)
	if err != nil {
		return View{}, err
	}
	if active {
		if err := m.Controller.Stop(ctx, id); err != nil {
			return View{}, fmt.Errorf("stop capture worker: %w", err)
		}
	}
	return m.Get(ctx, id)
}

func (m *Manager) Get(ctx context.Context, id string) (View, error) {
	session, err := m.Store.ReadSession(id)
	if err != nil {
		return View{}, err
	}
	active := false
	if m.Controller != nil {
		active, err = m.Controller.Active(ctx, id)
		if err != nil {
			return View{}, err
		}
	}
	status, statusErr := m.Store.ReadWorkerStatus(id)
	view := View{Session: session, State: StateStarting, Active: active}
	if statusErr == nil {
		view.Worker = &status
		view.State = status.State
		view.StoragePressure = status.State == StateStoragePressure
	}
	view.CurrentFiles, view.CurrentBytes, err = m.Store.Usage(id)
	if err != nil {
		return View{}, err
	}
	if manifest, manifestErr := m.Store.ReadManifest(id); manifestErr == nil {
		view.Manifest = &manifest
	}
	if _, hold, holdErr := m.effectiveRetentionLock(id, session.Request.RetentionLock); holdErr != nil {
		return View{}, holdErr
	} else {
		view.EvidenceHold = hold
	}
	return view, nil
}

func (m *Manager) List(ctx context.Context) ([]View, error) {
	ids, err := m.Store.ListSessionIDs()
	if err != nil {
		return nil, err
	}
	views := make([]View, 0, len(ids))
	for _, id := range ids {
		view, err := m.Get(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("inspect capture %s: %w", id, err)
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Session.StartedAt.After(views[j].Session.StartedAt) })
	return views, nil
}

func (m *Manager) ReadArtifactChunk(ctx context.Context, id, fileName string, offset int64, length int) (ArtifactChunk, error) {
	view, err := m.Get(ctx, id)
	if err != nil {
		return ArtifactChunk{}, err
	}
	if view.Active || view.Manifest == nil {
		return ArtifactChunk{}, errors.New("capture artifacts are exportable only after finalization")
	}
	return m.Store.ReadArtifactChunk(id, fileName, offset, length)
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}
