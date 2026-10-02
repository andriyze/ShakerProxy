package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
	"shakerproxy.dev/shakerproxy/internal/vpn"
)

// DefaultLabRecordingInterval is how often gatewayd checks that the lab is
// being recorded. A changed setting or network plan is acted on within a
// couple of seconds through Wake.
const DefaultLabRecordingInterval = 30 * time.Second

// LabRecorder keeps lab traffic recorded whenever a confirmed lab plan
// routes, so nobody has to remember to start a capture. It starts the
// automatic recording (capture.LabRecordingRequest), starts a new one when a
// recording reaches its 24 hour end, after a reboot and when the lab plan
// changes, and stops it when the lab is turned off, rolled back or bypassed.
// A manual capture replaces it; recording resumes when the manual capture
// ends. Administrators can turn it off (StateStore.SetLabRecording).
type LabRecorder struct {
	Store    *StateStore
	Captures *capture.Manager
	// Source returns the capture interface of the active lab plan and the
	// plan hash, as for a manual capture.
	Source func(context.Context) (capture.Source, string, error)
	// NewCaptureAllowed reports whether CPU, memory and disk allow a new
	// capture; nil allows it.
	NewCaptureAllowed func() bool
	ConfigLock        *configlock.Manager
	Logger            *slog.Logger
	Interval          time.Duration
	Now               func() time.Time
	// VPN makes this the VPN recorder: it records the WireGuard interface
	// while VPN mode is up, beside the lab recording (a pcapng file cannot
	// mix the lab's Ethernet frames with the VPN's raw IP packets for Zeek
	// and Suricata). It returns the running VPN segment, or nil.
	VPN func() *trafficpolicy.Segment

	mu          sync.Mutex
	status      gatewayprotocol.LabRecordingStatus
	lastProblem string
	lastTidy    string
	wake        chan struct{}
	wakeOnce    sync.Once
}

// Run checks immediately and then on every interval or wake until ctx ends.
func (r *LabRecorder) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultLabRecordingInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		r.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-r.wakeChannel():
			// Let the request that woke us release the configuration lock.
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}

// Wake asks for a check soon, after a setting or the network plan changed.
func (r *LabRecorder) Wake() {
	select {
	case r.wakeChannel() <- struct{}{}:
	default:
	}
}

func (r *LabRecorder) wakeChannel() chan struct{} {
	r.wakeOnce.Do(func() { r.wake = make(chan struct{}, 1) })
	return r.wake
}

// Status is the result of the latest check; nil before the first one.
func (r *LabRecorder) Status() *gatewayprotocol.LabRecordingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status.CheckedAt.IsZero() {
		return nil
	}
	status := r.status
	return &status
}

// Tick makes the recording match the lab and the setting once.
func (r *LabRecorder) Tick(ctx context.Context) gatewayprotocol.LabRecordingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	status := r.check(ctx)
	status.CheckedAt = r.now()
	r.status = status
	return status
}

func (r *LabRecorder) check(ctx context.Context) gatewayprotocol.LabRecordingStatus {
	state := r.Store.Get()
	status := gatewayprotocol.LabRecordingStatus{Enabled: !state.LabRecordingOff}
	if r.Captures == nil {
		status.Reason = "Packet capture is not available on this appliance."
		return status
	}
	views, err := r.Captures.List(ctx)
	if err != nil {
		r.problem("capture status is unavailable", err)
		status.Reason = "Capture status is unavailable. Run `shakerproxy capture list` for details."
		return status
	}
	var active, manual *capture.View
	for index := range views {
		view := &views[index]
		switch {
		case !view.Active:
		case !view.Session.Request.Automatic:
			if manual == nil {
				manual = view
			}
		case r.owns(*view) && active == nil:
			active = view
		}
	}
	defer r.tidy(ctx)
	target, notRouting := r.target(state)
	// A manual capture records the lab interface; the VPN recording keeps
	// running beside it.
	if manual != nil && r.VPN == nil {
		status.Recording, status.SessionID, status.Manual = true, manual.Session.ID, true
		status.Reason = "A manual capture is recording the lab. Automatic recording resumes when it ends."
		return status
	}
	if active != nil {
		if status.Enabled && target != nil && active.Session.PolicyRevision == target.revision {
			status.Recording, status.SessionID = true, active.Session.ID
			r.recovered()
			return status
		}
		why := "the lab stopped routing"
		switch {
		case !status.Enabled:
			why = "automatic recording was turned off"
		case target != nil:
			why = "the lab network plan changed"
		case r.VPN != nil:
			why = "VPN mode stopped"
		}
		if err := r.withLock(ctx, func() error {
			_, err := r.Captures.Stop(ctx, active.Session.ID)
			return err
		}); err != nil {
			r.problem("automatic lab recording could not be stopped", err)
			status.Recording, status.SessionID = true, active.Session.ID
			status.Reason = "Stopping the lab recording failed: " + err.Error()
			return status
		}
		r.log(slog.LevelInfo, "stopped the automatic lab recording", "capture_id", active.Session.ID, "reason", why)
		if status.Enabled && target != nil {
			// The new plan's recording starts once this one has stopped.
			status.Reason = "Restarting the lab recording for the new network plan."
			return status
		}
	}
	switch {
	case !status.Enabled:
		status.Reason = "Automatic lab recording is turned off. Turn it on from Traffic or with `shakerproxy capture auto on`."
	case target == nil:
		status.Reason = notRouting
	default:
		id, err := r.start(ctx, state.OperatingMode, *target)
		if err != nil {
			r.problem("automatic lab recording could not start", err)
			status.Reason = "Lab traffic is not being recorded: " + err.Error() + "."
			return status
		}
		r.recovered()
		status.Recording, status.SessionID = true, id
	}
	return status
}

// recordingTarget is what a recorder should be recording now.
type recordingTarget struct {
	revision string
	// source is nil for the lab, whose interface comes from Source.
	source  *capture.Source
	request func(revision string) capture.StartRequest
}

// owns reports whether an automatic recording is this recorder's.
func (r *LabRecorder) owns(view capture.View) bool {
	return (view.Session.Source.InterfaceName == vpn.InterfaceName) == (r.VPN != nil)
}

func (r *LabRecorder) target(state persistedState) (*recordingTarget, string) {
	if r.VPN == nil {
		plan, notRouting := labRecordingPlan(state)
		if plan == nil {
			return nil, notRouting
		}
		return &recordingTarget{revision: plan.PlanHash, request: capture.LabRecordingRequest}, ""
	}
	if state.EmergencyBypass {
		return nil, "Emergency bypass is on, so VPN traffic is not recorded."
	}
	segment := r.VPN()
	if segment == nil {
		return nil, "VPN mode is off."
	}
	// The revision names the interface's network, not its devices, so adding
	// or revoking a device does not restart the recording.
	digest := sha256.Sum256([]byte("wireguard-vpn\x00" + segment.Interface + "\x00" + segment.IPv4CIDR + "\x00" + segment.IPv6Prefix))
	return &recordingTarget{
		revision: "vpn-" + hex.EncodeToString(digest[:16]),
		source:   &capture.Source{InterfaceName: segment.Interface, InterfaceStableID: "wireguard:" + segment.Interface},
		request:  capture.VPNRecordingRequest,
	}, ""
}

// labRecordingPlan returns the plan to record, or why there is none.
func labRecordingPlan(state persistedState) (*networkplan.StagedPlan, string) {
	switch {
	case state.EmergencyBypass:
		return nil, "Emergency bypass is on, so lab traffic is not recorded."
	case state.OperatingMode != gatewayprotocol.ModeRouted:
		return nil, "The lab is off. Recording starts when a lab network plan is applied and confirmed."
	}
	plan := state.activeNetworkPlan()
	if plan == nil {
		return nil, "No lab network plan is confirmed yet. Recording starts when one is."
	}
	return plan, ""
}

func (r *LabRecorder) start(ctx context.Context, operatingMode string, target recordingTarget) (string, error) {
	if r.NewCaptureAllowed != nil && !r.NewCaptureAllowed() {
		return "", errors.New("disk, memory or CPU pressure is critical")
	}
	var source capture.Source
	revision := target.revision
	if target.source != nil {
		source = *target.source
	} else {
		if r.Source == nil {
			return "", errors.New("the lab interface is unknown")
		}
		var err error
		if source, revision, err = r.Source(ctx); err != nil {
			return "", err
		}
	}
	var view capture.View
	err := r.withLock(ctx, func() error {
		var startErr error
		view, startErr = r.Captures.Start(ctx, target.request(revision), source, operatingMode, revision)
		return startErr
	})
	if err != nil {
		return "", err
	}
	r.log(slog.LevelInfo, "recording lab traffic", "capture_id", view.Session.ID, "interface", source.InterfaceName, "plan_hash", revision)
	return view.Session.ID, nil
}

// tidy keeps finished automatic recordings within their disk bound.
func (r *LabRecorder) tidy(ctx context.Context) {
	err := r.Captures.TidyLabRecordings(ctx, capture.LabRecordingKeep)
	switch {
	case err == nil:
		r.lastTidy = ""
	case err.Error() != r.lastTidy:
		r.lastTidy = err.Error()
		r.log(slog.LevelWarn, "old lab recordings could not be tidied", "error", err)
	}
}

// withLock serializes capture starts and stops with the StartCapture and
// StopCapture requests, which hold the capture configuration lock.
func (r *LabRecorder) withLock(ctx context.Context, action func() error) error {
	if r.ConfigLock == nil {
		return action()
	}
	lockContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	guard, err := r.ConfigLock.Acquire(lockContext, configlock.Request{OperationID: "lab-recording", Category: configlock.CategoryCapture, Actor: "gatewayd"})
	cancel()
	if err != nil {
		return errors.New("another appliance change is in progress; retrying shortly")
	}
	defer guard.Release()
	return action()
}

// problem logs each distinct failure once instead of every interval.
func (r *LabRecorder) problem(message string, err error) {
	if err.Error() == r.lastProblem {
		return
	}
	r.lastProblem = err.Error()
	r.log(slog.LevelWarn, message, "error", err)
}

func (r *LabRecorder) recovered() { r.lastProblem = "" }

func (r *LabRecorder) log(level slog.Level, message string, attributes ...any) {
	if r.Logger != nil {
		r.Logger.Log(context.Background(), level, message, attributes...)
	}
}

func (r *LabRecorder) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}
