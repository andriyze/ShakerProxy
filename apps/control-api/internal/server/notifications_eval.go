package server

import (
	"context"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/labrouting"
	"shakerproxy.dev/shakerproxy/internal/notify"
)

// notifyState holds the evaluator's in-memory memory: which trigger+subject
// last fired (so a chatty condition is one notification per window), and which
// devices were already known on the first pass (so turning notifications on,
// or a restart, does not announce every device already present).
type notifyState struct {
	lastFired map[string]time.Time
	known     map[string]bool
	seeded    bool
}

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
	s.notifyEvalState = &notifyState{lastFired: map[string]time.Time{}, known: map[string]bool{}}
	tick := func() {
		if !s.notifyConfigAvailable() {
			return
		}
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
		s.deliverNotifications(ctx, config, fired, now)
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

func (s *Server) deliverNotifications(ctx context.Context, config notify.Config, fired []notify.Notification, now time.Time) {
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
			if err := s.notifyDeliverer.Deliver(ctx, channel, n); err != nil {
				s.logger.Warn("notification delivery failed", "channel", channel.ID, "kind", channel.Kind, "error", err)
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
		if s.notifyEvalState != nil {
			s.notifyEvalState.seeded = true
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
	if s.notifyEvalState == nil {
		return
	}
	report := s.currentLabRouting(ctx)
	for _, device := range report.Devices {
		if device.DeviceID != "" {
			s.notifyEvalState.known[device.DeviceID] = true
		}
	}
	s.notifyEvalState.seeded = true
}

// noteNewDevice reports whether deviceID is newly seen, and records it. The
// first pass only seeds and never reports new, so startup is quiet.
func (s *Server) noteNewDevice(deviceID string) bool {
	state := s.notifyEvalState
	if state == nil {
		return false
	}
	if !state.seeded {
		state.known[deviceID] = true
		return false
	}
	if state.known[deviceID] {
		return false
	}
	state.known[deviceID] = true
	return true
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
