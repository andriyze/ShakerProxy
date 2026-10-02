package server

import (
	"net/http"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

// Wi-Fi visibility: a passive monitor interface records what lab devices do
// on the radio. These endpoints show whether it can run, why not, and turn
// it on and off; the CLI (`shakerproxy wifi`), MCP and the UI use them.

type wifiVisibilityView struct {
	gatewayprotocol.WiFiMonitorStatus
	Notes []string `json:"notes"`
}

func wifiVisibility(status gatewayprotocol.WiFiMonitorStatus) wifiVisibilityView {
	if status.Adapters == nil {
		status.Adapters = []gatewayprotocol.WiFiAdapter{}
	}
	view := wifiVisibilityView{WiFiMonitorStatus: status, Notes: []string{
		"Listening is passive: ShakerProxy never transmits, injects or disconnects anything.",
		"Only frames of lab devices and the lab's own network are recorded unless nearby devices are turned on.",
		"Wi-Fi data frames stay encrypted (WPA2/WPA3); what is visible is searching, joining, roaming and leaving.",
	}}
	switch status.ChannelMode {
	case gatewayprotocol.WiFiChannelHop:
		view.Notes = append(view.Notes, "Hopping across channels misses frames sent while the radio listens elsewhere; choose a fixed channel to follow one device closely.")
	case gatewayprotocol.WiFiChannelAccessPoint:
		view.Notes = append(view.Notes, "The monitor shares the lab access point's radio and hears only its channel.")
	}
	if status.Settings.Nearby {
		view.Notes = append(view.Notes, "Nearby devices and networks are recorded; that data is deleted after 24 hours.")
	}
	return view
}

func (s *Server) getWiFiVisibility(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "Wi-Fi visibility does not accept query parameters")
		return
	}
	var status gatewayprotocol.WiFiMonitorStatus
	if err := s.gateway.Call(r.Context(), "GetWiFiMonitor", gatewayprotocol.EmptyParams{}, &status); err != nil {
		writeError(w, http.StatusServiceUnavailable, "wifi_visibility_unavailable", "Wi-Fi visibility is unavailable; check that shakerproxy-gatewayd is running")
		return
	}
	writeJSON(w, http.StatusOK, wifiVisibility(status))
}

type wifiVisibilityRequest struct {
	Enabled     *bool   `json:"enabled"`
	Adapter     *string `json:"adapter"`
	ChannelMode *string `json:"channel_mode"`
	Channel     *int    `json:"channel"`
	Nearby      *bool   `json:"nearby"`
	// AcknowledgeNearby confirms that recording nearby devices records
	// people who are not part of the test.
	AcknowledgeNearby bool `json:"acknowledge_nearby"`
}

// putWiFiVisibility changes lab behaviour, like the DNS switches: an
// administrator session or an API token with lab:write.
func (s *Server) putWiFiVisibility(w http.ResponseWriter, r *http.Request) {
	var request wifiVisibilityRequest
	if err := decodeJSON(r, &request); err != nil || request.Enabled == nil && request.Adapter == nil && request.ChannelMode == nil && request.Channel == nil && request.Nearby == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "send enabled, adapter, channel_mode, channel or nearby")
		return
	}
	var current gatewayprotocol.WiFiMonitorStatus
	if err := s.gateway.Call(r.Context(), "GetWiFiMonitor", gatewayprotocol.EmptyParams{}, &current); err != nil {
		writeError(w, http.StatusServiceUnavailable, "wifi_visibility_unavailable", "Wi-Fi visibility is unavailable; check that shakerproxy-gatewayd is running")
		return
	}
	settings := current.Settings
	if settings.ChannelMode == "" {
		settings.ChannelMode = gatewayprotocol.WiFiChannelAuto
	}
	if request.Enabled != nil {
		settings.Enabled = *request.Enabled
	}
	if request.Adapter != nil {
		settings.Adapter = strings.TrimSpace(*request.Adapter)
	}
	if request.ChannelMode != nil {
		settings.ChannelMode = *request.ChannelMode
		if settings.ChannelMode != gatewayprotocol.WiFiChannelFixed {
			settings.Channel = 0
		}
	}
	if request.Channel != nil {
		settings.Channel = *request.Channel
		if request.ChannelMode == nil && *request.Channel != 0 {
			settings.ChannelMode = gatewayprotocol.WiFiChannelFixed
		}
	}
	if request.Nearby != nil {
		settings.Nearby = *request.Nearby
	}
	if err := settings.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if settings.Nearby && !current.Settings.Nearby && !request.AcknowledgeNearby {
		writeError(w, http.StatusBadRequest, "nearby_not_acknowledged", "Recording nearby devices and networks records people who are not part of your test. Send acknowledge_nearby: true to confirm; that data is deleted after 24 hours.")
		return
	}
	var status gatewayprotocol.WiFiMonitorStatus
	params := gatewayprotocol.SetWiFiMonitorParams{Settings: settings, AcknowledgeNearby: request.AcknowledgeNearby}
	if err := s.gateway.Call(r.Context(), "SetWiFiMonitor", params, &status); err != nil {
		writeError(w, http.StatusConflict, "wifi_visibility_apply_failed", err.Error())
		return
	}
	s.logger.Info("Wi-Fi visibility changed", "username", sessionUsername(r.Context()), "enabled", settings.Enabled, "channel_mode", settings.ChannelMode, "channel", settings.Channel, "nearby", settings.Nearby, "adapter", status.Adapter)
	writeJSON(w, http.StatusOK, wifiVisibility(status))
}
