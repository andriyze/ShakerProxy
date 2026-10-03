package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/notify"
)

// Notifications tell a tester when something notable happens — a new device, a
// device whose traffic bypasses ShakerProxy, a secret sent in the clear, a
// connection to a flagged domain — and deliver it to an in-app list and to
// webhooks they configure. The configuration is a standing change, so it needs
// the administrator password like the other integrations. A notification
// states what happened and the subject, never a secret value.

type notifyConfigView struct {
	Available bool             `json:"available"`
	Enabled   bool             `json:"enabled"`
	Revision  int              `json:"revision"`
	UpdatedAt time.Time        `json:"updated_at,omitzero"`
	UpdatedBy string           `json:"updated_by,omitempty"`
	Channels  []notify.Channel `json:"channels"`
	Rules     []notify.Rule    `json:"rules"`
	Unread    int              `json:"unread"`
}

func (s *Server) notifyConfigAvailable() bool {
	return s.notifyConfigPath != "" && s.notifyLogPath != ""
}

func (s *Server) notifyView(config notify.Config) notifyConfigView {
	unread := 0
	if log, err := notify.LoadLog(s.notifyLogPath); err == nil {
		unread = log.Unread()
	}
	// Neither a channel's secret nor its URL is returned: a Slack
	// incoming-webhook URL can post on its own, so it is a credential too
	// (readable here by any system:read token). Both become markers that
	// a write sends back to keep the stored value.
	channels := make([]notify.Channel, len(config.Channels))
	for index, channel := range config.Channels {
		if channel.Secret != "" {
			channel.Secret = "set"
		}
		channel.URL = notify.MaskedURL(channel.URL)
		channels[index] = channel
	}
	return notifyConfigView{
		Available: true,
		Enabled:   config.Enabled(),
		Revision:  config.Revision,
		UpdatedAt: config.UpdatedAt,
		UpdatedBy: config.UpdatedBy,
		Channels:  channels,
		Rules:     append([]notify.Rule{}, config.Rules...),
		Unread:    unread,
	}
}

func (s *Server) getNotifyConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "the notifications endpoint does not accept query parameters")
		return
	}
	if !s.notifyConfigAvailable() {
		writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "notifications are not configured on this appliance")
		return
	}
	config, err := notify.LoadConfig(s.notifyConfigPath)
	if err != nil {
		s.logger.Error("notifications config could not be read", "error", err)
		writeError(w, http.StatusInternalServerError, "notifications_config_failed", "the notifications configuration could not be read")
		return
	}
	writeJSON(w, http.StatusOK, s.notifyView(config))
}

type putNotifyRequest struct {
	Channels         []notify.Channel `json:"channels"`
	Rules            []notify.Rule    `json:"rules"`
	ExpectedRevision *int             `json:"expected_revision"`
	Password         string           `json:"password"`
}

func (s *Server) putNotifyConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.notifyConfigAvailable() {
		writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "notifications are not configured on this appliance")
		return
	}
	var request putNotifyRequest
	if err := decodeJSONBounded(r, &request, 32<<10); err != nil {
		writeDecodeError(w, err, "notifications configuration")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	current, err := notify.LoadConfig(s.notifyConfigPath)
	if err != nil {
		s.logger.Error("notifications config could not be read", "error", err)
		writeError(w, http.StatusInternalServerError, "notifications_config_failed", "the notifications configuration could not be read")
		return
	}
	if request.ExpectedRevision != nil && *request.ExpectedRevision != current.Revision {
		writeError(w, http.StatusConflict, "revision_conflict", "the configuration changed since it was read; reload and try again")
		return
	}
	next := notify.DefaultConfig()
	next.Channels = mergeChannelSecrets(request.Channels, current)
	next.Rules = request.Rules
	next.Revision = current.Revision + 1
	next.UpdatedAt = time.Now().UTC()
	next.UpdatedBy = sessionUsername(r.Context())
	if err := next.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "notifications_rejected", err.Error())
		return
	}
	if err := notify.SaveConfig(s.notifyConfigPath, next); err != nil {
		s.logger.Error("notifications config could not be written", "error", err)
		writeError(w, http.StatusInternalServerError, "notifications_write_failed", "the notifications configuration could not be saved")
		return
	}
	s.logger.Info("notifications configuration changed", "actor", next.UpdatedBy, "enabled", next.Enabled, "revision", next.Revision, "channels", len(next.Channels), "rules", len(next.Rules))
	writeJSON(w, http.StatusOK, s.notifyView(next))
}

// mergeChannelSecrets keeps an existing channel's secret when the caller sends
// the "set" marker, and its URL when the caller sends the masked URL back (so
// neither is exposed or cleared by a round-trip through the UI); a new value
// is taken only when one is given.
func mergeChannelSecrets(incoming []notify.Channel, current notify.Config) []notify.Channel {
	previous := map[string]notify.Channel{}
	for _, channel := range current.Channels {
		previous[channel.ID] = channel
	}
	out := make([]notify.Channel, 0, len(incoming))
	for _, channel := range incoming {
		channel.Name = strings.TrimSpace(channel.Name)
		channel.URL = strings.TrimSpace(channel.URL)
		stored, known := previous[channel.ID]
		if channel.Secret == "set" {
			channel.Secret = stored.Secret
		}
		if known && stored.URL != "" && channel.URL == notify.MaskedURL(stored.URL) {
			channel.URL = stored.URL
		}
		out = append(out, channel)
	}
	return out
}

type testNotifyRequest struct {
	Channel string `json:"channel"`
}

func (s *Server) postNotifyTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.notifyConfigAvailable() {
		writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "notifications are not configured on this appliance")
		return
	}
	var request testNotifyRequest
	if err := decodeJSONBounded(r, &request, 4<<10); err != nil {
		writeDecodeError(w, err, "test notification")
		return
	}
	config, err := notify.LoadConfig(s.notifyConfigPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notifications_config_failed", "the notifications configuration could not be read")
		return
	}
	var target *notify.Channel
	for index := range config.Channels {
		if config.Channels[index].ID == request.Channel {
			target = &config.Channels[index]
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusBadRequest, "unknown_channel", "no channel with that id")
		return
	}
	candidate := notify.TestCandidate()
	n := notify.Notification{ID: "ntf-test", CreatedAt: time.Now().UTC(), Trigger: candidate.Trigger, Severity: candidate.Severity, Title: candidate.Title, Body: candidate.Body}
	if target.Kind == notify.ChannelInApp {
		if err := notify.AppendLog(s.notifyLogPath, []notify.Notification{n}, time.Now()); err != nil {
			writeError(w, http.StatusInternalServerError, "notifications_write_failed", "the test notification could not be stored")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"delivered": true, "channel": target.ID})
		return
	}
	if err := s.notifyDeliverer.Deliver(r.Context(), *target, n); err != nil {
		writeError(w, http.StatusBadGateway, "delivery_failed", "the test notification could not be delivered: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"delivered": true, "channel": target.ID})
}

type notificationsListView struct {
	Schema        int                   `json:"schema"`
	Unread        int                   `json:"unread"`
	Notifications []notify.Notification `json:"notifications"`
}

func (s *Server) listNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.notifyConfigAvailable() {
		writeJSON(w, http.StatusOK, notificationsListView{Schema: 1, Notifications: []notify.Notification{}})
		return
	}
	log, err := notify.LoadLog(s.notifyLogPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notifications_read_failed", "the notifications could not be read")
		return
	}
	limit := 50
	if value := r.URL.Query().Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 1 && parsed <= 200 {
			limit = parsed
		}
	}
	writeJSON(w, http.StatusOK, notificationsListView{Schema: 1, Unread: log.Unread(), Notifications: log.Recent(limit)})
}

type markReadRequest struct {
	IDs []string `json:"ids"`
}

func (s *Server) markNotificationsRead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.notifyConfigAvailable() {
		writeJSON(w, http.StatusOK, map[string]any{"changed": 0})
		return
	}
	var request markReadRequest
	if err := decodeJSONBounded(r, &request, 16<<10); err != nil {
		writeDecodeError(w, err, "notifications read request")
		return
	}
	changed, err := notify.MarkRead(s.notifyLogPath, request.IDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notifications_write_failed", "the notifications could not be updated")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changed": changed})
}
