package server

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/labrouting"
	"shakerproxy.dev/shakerproxy/internal/notify"
)

// notifyState holds the evaluator's memory: which trigger+subject last fired
// (so a chatty condition is one notification per window), and which devices
// were already known on the first pass (so turning notifications on does not
// announce every device already present). It is saved next to the log, so a
// restart neither re-sends every still-active condition nor forgets which
// devices it has seen.
type notifyState struct {
	lastFired map[string]time.Time
	known     map[string]bool
	seeded    bool
	// dirty is set when the state changed since it was last saved.
	dirty bool
	// deliveries feeds the webhook/Slack worker, so a slow or failing
	// endpoint (each one retried) never stalls the evaluation pass.
	deliveries chan notifyDelivery
}

type notifyDelivery struct {
	channel      notify.Channel
	notification notify.Notification
}

// notifyDeliveryQueue bounds the deliveries waiting for the worker.
const notifyDeliveryQueue = 64

// notifyEvalWindow is how far back each pass looks for detections and flagged
// domains. It is a bounded, recent window, not a full-table scan.
const notifyEvalWindow = 15 * time.Minute

// RunNotifications evaluates the notable moments on an interval and delivers
// notifications to the configured channels. It does nothing until a rule is
// enabled.
func (s *Server) RunNotifications(ctx context.Context, interval time.Duration) {
	if interval < time.Second {
		interval = 30 * time.Second
	}
	s.notifyEvalState = s.loadNotifyState()
	s.notifyEvalState.deliveries = make(chan notifyDelivery, notifyDeliveryQueue)
	go s.runNotifyDeliveries(ctx, s.notifyEvalState.deliveries)
	tick := func() {
		if !s.notifyConfigAvailable() {
			return
		}
		defer s.saveNotifyState()
		config, err := notify.LoadConfig(s.notifyConfigPath)
		if err != nil {
			s.logger.Warn("notifications config could not be read", "error", err)
			return
		}
		if !config.Enabled() {
			// Still seed known devices so enabling later does not flood.
			s.seedKnownDevices(ctx)
			return
		}
		candidates := s.gatherNotifyCandidates(ctx)
		now := time.Now().UTC()
		fired, updated := notify.Evaluate(candidates, config, s.notifyEvalState.lastFired, now)
		s.notifyEvalState.lastFired = updated
		if len(fired) == 0 {
			return
		}
		s.notifyEvalState.dirty = true
		s.deliverNotifications(config, fired, now)
	}
	tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}

// notifyStatePath is the evaluator state file beside the in-app log.
func (s *Server) notifyStatePath() string {
	return strings.TrimSuffix(s.notifyLogPath, filepath.Ext(s.notifyLogPath)) + "-state.json"
}

func (s *Server) loadNotifyState() *notifyState {
	state := &notifyState{lastFired: map[string]time.Time{}, known: map[string]bool{}}
	if !s.notifyConfigAvailable() {
		return state
	}
	saved, err := notify.LoadEvalState(s.notifyStatePath())
	if err != nil {
		s.logger.Warn("notifications state could not be read; starting fresh", "error", err)
		return state
	}
	state.lastFired, state.seeded = saved.LastFired, saved.Seeded
	for _, id := range saved.Known {
		state.known[id] = true
	}
	return state
}

func (s *Server) saveNotifyState() {
	state := s.notifyEvalState
	if state == nil || !state.dirty {
		return
	}
	known := make([]string, 0, len(state.known))
	for id := range state.known {
		known = append(known, id)
	}
	if err := notify.SaveEvalState(s.notifyStatePath(), notify.EvalState{Seeded: state.seeded, LastFired: state.lastFired, Known: known}); err != nil {
		s.logger.Warn("notifications state could not be saved", "error", err)
		return
	}
	state.dirty = false
}

func (s *Server) deliverNotifications(config notify.Config, fired []notify.Notification, now time.Time) {
	channels := map[string]notify.Channel{}
	for _, channel := range config.Channels {
		channels[channel.ID] = channel
	}
	// Every fired notification is stored in the in-app list, regardless of
	// which channels the rule also named.
	if err := notify.AppendLog(s.notifyLogPath, fired, now); err != nil {
		s.logger.Warn("notification could not be stored", "error", err)
	}
	for _, n := range fired {
		for _, id := range n.Channels {
			channel, ok := channels[id]
			if !ok || !channel.Enabled || channel.Kind == notify.ChannelInApp {
				continue
			}
			select {
			case s.notifyEvalState.deliveries <- notifyDelivery{channel: channel, notification: n}:
			default:
				s.logger.Warn("notification delivery queue is full; dropped", "channel", channel.ID, "kind", channel.Kind, "notification", n.ID)
			}
		}
	}
}

// runNotifyDeliveries sends queued notifications one at a time, retrying
// transient failures.
func (s *Server) runNotifyDeliveries(ctx context.Context, deliveries <-chan notifyDelivery) {
	for {
		select {
		case <-ctx.Done():
			return
		case delivery := <-deliveries:
			if err := notify.DeliverWithRetry(ctx, s.notifyDeliverer, delivery.channel, delivery.notification); err != nil {
				s.logger.Warn("notification delivery failed", "channel", delivery.channel.ID, "kind", delivery.channel.Kind, "notification", delivery.notification.ID, "error", err)
			}
		}
	}
}

// gatherNotifyCandidates reads the recent lab-routing report, recent detections
// and recent flagged-domain contacts, and turns them into candidates. Device
// names come from the routing report where known.
func (s *Server) gatherNotifyCandidates(ctx context.Context) []notify.Candidate {
	var candidates []notify.Candidate
	names := map[string]string{}

	report := s.currentLabRouting(ctx)
	if report.Available {
		for _, device := range report.Devices {
			if device.DeviceID != "" && device.DisplayName != "" {
				names[device.DeviceID] = device.DisplayName
			}
			switch device.Routing {
			case labrouting.Bypassing:
				candidates = append(candidates, notify.BypassingCandidate(device.DeviceID, device.DisplayName, device.Address, device.Reason))
			}
			if device.DeviceID != "" && s.noteNewDevice(device.DeviceID) {
				candidates = append(candidates, notify.NewDeviceCandidate(device.DeviceID, device.DisplayName, device.Address))
			}
		}
		// After the first enabled pass the current devices are known, so
		// later passes announce only genuinely new ones.
		if s.notifyEvalState != nil && !s.notifyEvalState.seeded {
			s.notifyEvalState.seeded, s.notifyEvalState.dirty = true, true
		}
	}

	candidates = append(candidates, s.detectionCandidates(ctx, names)...)
	return candidates
}

// detectionCandidates reads recent events and makes candidates for cleartext
// exposures, other native detections / Suricata alerts, and flagged domains.
func (s *Server) detectionCandidates(ctx context.Context, names map[string]string) []notify.Candidate {
	if s.eventReader == nil {
		return nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, labRoutingLookupTimeout)
	defer cancel()
	page, err := s.eventReader.QueryRecent(queryCtx, ingest.RecentEventQuery{Limit: 400, TimeAnchor: time.Now().UTC()})
	if err != nil {
		s.logger.Warn("notifications could not read recent events", "error", err)
		return nil
	}
	cutoff := time.Now().Add(-notifyEvalWindow)
	var candidates []notify.Candidate
	for _, event := range page.Events {
		if event.OccurredAt.Before(cutoff) {
			continue
		}
		name := names[event.DeviceID]
		switch {
		case event.DetectionType == "CLEARTEXT_CREDENTIAL" && (event.DetectionState == "" || event.DetectionState == "OPEN"):
			host := firstNonEmpty(event.HTTPHost, event.TLSServerName)
			candidates = append(candidates, notify.CleartextCandidate(event.DeviceID, name, host, strings.ToLower(event.DetectionScope), event.DetectionSummary))
		case event.DetectionType != "" && (event.DetectionState == "" || event.DetectionState == "OPEN"):
			candidates = append(candidates, notify.SecurityAlertCandidate(event.DeviceID, name, event.DetectionType, detectionSummary(event), detectionSeverity(event.DetectionSeverity)))
		case event.AlertSignature != "":
			candidates = append(candidates, notify.SecurityAlertCandidate(event.DeviceID, name, "suricata.alert", event.AlertSignature, alertSeverity(event.AlertSeverity)))
		}
		if domain := firstNonEmpty(event.DNSQuery, event.TLSServerName, event.HTTPHost); domain != "" {
			if category := notify.FlaggedCategory(domain); category != "" {
				candidates = append(candidates, notify.FlaggedDomainCandidate(event.DeviceID, name, strings.ToLower(domain), category))
			}
		}
	}
	return candidates
}

// seedKnownDevices records the current devices so that enabling notifications
// later does not announce devices already present.
func (s *Server) seedKnownDevices(ctx context.Context) {
	s.seedKnownDevicesFrom(s.currentLabRouting(ctx))
}

// seedKnownDevicesFrom seeds only from an available report: an unavailable
// one lists no devices, and marking the state seeded from it would announce
// every device already present as new once the report is back.
func (s *Server) seedKnownDevicesFrom(report labRoutingReport) {
	state := s.notifyEvalState
	if state == nil || !report.Available {
		return
	}
	for _, device := range report.Devices {
		if device.DeviceID != "" && !state.known[device.DeviceID] {
			state.known[device.DeviceID], state.dirty = true, true
		}
	}
	if !state.seeded {
		state.seeded, state.dirty = true, true
	}
}

// noteNewDevice reports whether deviceID is newly seen, and records it. The
// first pass only seeds and never reports new, so startup is quiet.
func (s *Server) noteNewDevice(deviceID string) bool {
	state := s.notifyEvalState
	if state == nil || state.known[deviceID] {
		return false
	}
	state.known[deviceID], state.dirty = true, true
	return state.seeded
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func detectionSummary(event ingest.RecentEvent) string {
	if event.DetectionSummary != "" {
		return event.DetectionSummary
	}
	return strings.ReplaceAll(strings.ToLower(event.DetectionType), "_", " ")
}

func detectionSeverity(value string) notify.Severity {
	switch strings.ToUpper(value) {
	case "CRITICAL", "HIGH":
		return notify.SeverityCritical
	case "WARNING", "MEDIUM":
		return notify.SeverityWarning
	default:
		return notify.SeverityInfo
	}
}

func alertSeverity(value int) notify.Severity {
	switch {
	case value <= 1:
		return notify.SeverityCritical
	case value == 2:
		return notify.SeverityWarning
	default:
		return notify.SeverityInfo
	}
}
