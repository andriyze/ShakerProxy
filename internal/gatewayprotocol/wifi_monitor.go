package gatewayprotocol

import (
	"errors"
	"regexp"
	"time"
)

// Wi-Fi visibility: a passive monitor interface on a Wi-Fi adapter records
// the 802.11 management frames of lab devices (which networks they search
// for, when they join, roam and leave). It never transmits.

const WiFiMonitorSchema = 1

// Channel modes of the Wi-Fi monitor.
const (
	// WiFiChannelAuto listens on the lab access point's channel when
	// ShakerProxy runs it, and otherwise hops.
	WiFiChannelAuto  = "auto"
	WiFiChannelFixed = "fixed"
	WiFiChannelHop   = "hop"
	// WiFiChannelAccessPoint is the effective mode of a monitor sharing the
	// lab access point's radio: it follows the access point's channel.
	WiFiChannelAccessPoint = "access-point"
)

// WiFiNearbyRetentionHours is how long events about devices and networks
// that are not part of the lab are kept.
const WiFiNearbyRetentionHours = 24

var wifiAdapterPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// WiFiMonitorSettings are what the tester chooses.
type WiFiMonitorSettings struct {
	Enabled bool `json:"enabled"`
	// Adapter is the Wi-Fi interface to listen with; empty chooses one.
	Adapter     string `json:"adapter,omitempty"`
	ChannelMode string `json:"channel_mode"`
	// Channel is the 2.4 or 5 GHz channel for WiFiChannelFixed.
	Channel int `json:"channel,omitempty"`
	// Nearby records devices and networks that are not part of the lab.
	Nearby bool `json:"nearby"`
}

// Validate checks a settings change.
func (s WiFiMonitorSettings) Validate() error {
	if s.Adapter != "" && (!wifiAdapterPattern.MatchString(s.Adapter) || s.Adapter == "." || s.Adapter == "..") {
		return errors.New("Wi-Fi adapter name is invalid")
	}
	switch s.ChannelMode {
	case WiFiChannelAuto, WiFiChannelHop:
		if s.Channel != 0 {
			return errors.New("a channel is only chosen in fixed channel mode")
		}
	case WiFiChannelFixed:
		if !(s.Channel >= 1 && s.Channel <= 14 || s.Channel >= 32 && s.Channel <= 177) {
			return errors.New("choose a 2.4 GHz (1-14) or 5 GHz (32-177) channel")
		}
	default:
		return errors.New("channel mode must be auto, fixed or hop")
	}
	return nil
}

// SetWiFiMonitorParams changes the settings. Recording nearby devices
// needs AcknowledgeNearby: it records people who are not part of the test.
type SetWiFiMonitorParams struct {
	Settings          WiFiMonitorSettings `json:"settings"`
	AcknowledgeNearby bool                `json:"acknowledge_nearby,omitempty"`
}

// WiFiAdapter is one Wi-Fi interface on the host.
type WiFiAdapter struct {
	Interface        string `json:"interface"`
	Phy              string `json:"phy,omitempty"`
	MonitorSupported bool   `json:"monitor_supported"`
	// MonitorAlongsideAP: a monitor interface can be added while the
	// adapter serves the lab access point.
	MonitorAlongsideAP bool `json:"monitor_alongside_ap"`
	// AccessPoint is the adapter serving the lab Wi-Fi.
	AccessPoint bool `json:"access_point"`
	// InUse: the adapter has addresses or carries a route, so taking it
	// over could disconnect the host.
	InUse    bool     `json:"in_use"`
	Bands    []string `json:"bands"`
	Channels []int    `json:"channels"`
}

// WiFiMonitorStatus is GetWiFiMonitor's and SetWiFiMonitor's result.
type WiFiMonitorStatus struct {
	Schema   int                 `json:"schema"`
	Settings WiFiMonitorSettings `json:"settings"`
	// Available is false when no adapter can monitor; Reason says why in
	// plain words.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// Active: the monitor interface exists and the capture runs.
	Active                bool   `json:"active"`
	Interface             string `json:"interface,omitempty"`
	Adapter               string `json:"adapter,omitempty"`
	Phy                   string `json:"phy,omitempty"`
	SharedWithAccessPoint bool   `json:"shared_with_access_point"`
	// ChannelMode is the effective mode: fixed, hop or access-point.
	ChannelMode          string        `json:"channel_mode,omitempty"`
	Channel              int           `json:"channel,omitempty"`
	FrequencyMHz         int           `json:"frequency_mhz,omitempty"`
	HopChannels          []int         `json:"hop_channels,omitempty"`
	Capturing            bool          `json:"capturing"`
	WorkerRunning        bool          `json:"worker_running"`
	LabSSID              string        `json:"lab_ssid,omitempty"`
	LabDevices           int           `json:"lab_devices"`
	Adapters             []WiFiAdapter `json:"adapters"`
	LastError            string        `json:"last_error,omitempty"`
	NearbyRetentionHours int           `json:"nearby_retention_hours"`
	CheckedAt            time.Time     `json:"checked_at"`
}
