package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// wifiVisibility mirrors GET/PUT /api/v1/wifi-visibility.
type wifiVisibility struct {
	Settings struct {
		Enabled     bool   `json:"enabled"`
		Adapter     string `json:"adapter"`
		ChannelMode string `json:"channel_mode"`
		Channel     int    `json:"channel"`
		Nearby      bool   `json:"nearby"`
	} `json:"settings"`
	Available             bool   `json:"available"`
	Reason                string `json:"reason"`
	Active                bool   `json:"active"`
	Adapter               string `json:"adapter"`
	SharedWithAccessPoint bool   `json:"shared_with_access_point"`
	ChannelMode           string `json:"channel_mode"`
	Channel               int    `json:"channel"`
	HopChannels           []int  `json:"hop_channels"`
	Capturing             bool   `json:"capturing"`
	WorkerRunning         bool   `json:"worker_running"`
	LabSSID               string `json:"lab_ssid"`
	LabDevices            int    `json:"lab_devices"`
	Adapters              []struct {
		Interface          string   `json:"interface"`
		MonitorSupported   bool     `json:"monitor_supported"`
		MonitorAlongsideAP bool     `json:"monitor_alongside_ap"`
		AccessPoint        bool     `json:"access_point"`
		InUse              bool     `json:"in_use"`
		Bands              []string `json:"bands"`
	} `json:"adapters"`
	LastError            string   `json:"last_error"`
	NearbyRetentionHours int      `json:"nearby_retention_hours"`
	Notes                []string `json:"notes"`
}

func (c *cli) wifiCommand(args []string) error {
	flags := newFlags("wifi")
	adapter := flags.String("adapter", "", "Wi-Fi adapter to listen with")
	confirm := flags.Bool("confirm", false, "confirm recording nearby devices")
	positional, err := parseFlags("wifi", flags, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		positional = []string{"status"}
	}
	change := map[string]any{}
	switch strings.ToLower(positional[0]) {
	case "status", "show":
		if err := expectArgs("wifi", positional, 1, 1); err != nil {
			return err
		}
	case "on", "enable", "start":
		if err := expectArgs("wifi", positional, 1, 1); err != nil {
			return err
		}
		change["enabled"] = true
	case "off", "disable", "stop":
		if err := expectArgs("wifi", positional, 1, 1); err != nil {
			return err
		}
		change["enabled"] = false
	case "channel":
		if err := expectArgs("wifi", positional, 2, 2, "channel", "a channel number, auto or hop"); err != nil {
			return err
		}
		switch value := strings.ToLower(positional[1]); value {
		case "auto", "hop":
			change["channel_mode"] = value
		default:
			channel, err := strconv.Atoi(value)
			if err != nil || channel < 1 {
				return usagef("wifi", "%q is not a channel: use a number (1-13, 36, 149, ...), auto or hop.", positional[1])
			}
			change["channel_mode"], change["channel"] = "fixed", channel
		}
	case "nearby":
		if err := expectArgs("wifi", positional, 2, 2, "nearby", "on or off"); err != nil {
			return err
		}
		enabled, err := onOff("wifi", positional[1])
		if err != nil {
			return err
		}
		if enabled && !*confirm {
			return usagef("wifi", "Recording nearby devices and networks records people who are not part of your test (kept 24 hours). Run `shakerproxy wifi nearby on --confirm` to do it anyway.")
		}
		change["nearby"] = enabled
		change["acknowledge_nearby"] = enabled
	default:
		return usagef("wifi", "Use `shakerproxy wifi status`, `wifi on`, `wifi off`, `wifi channel <n|auto|hop>` or `wifi nearby on|off`.")
	}
	if *adapter != "" {
		change["adapter"] = *adapter
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	defer session.close()
	var view wifiVisibility
	var raw []byte
	if len(change) == 0 {
		raw, err = session.getJSON("/api/v1/wifi-visibility", &view)
	} else {
		raw, err = session.do(http.MethodPut, "/api/v1/wifi-visibility", change)
		if err == nil {
			err = json.Unmarshal(raw, &view)
		}
	}
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	c.printWiFi(view)
	return nil
}

func (c *cli) printWiFi(view wifiVisibility) {
	switch {
	case view.Active:
		where := fmt.Sprintf("channel %d", view.Channel)
		switch view.ChannelMode {
		case "hop":
			where = fmt.Sprintf("hopping over channels %s", joinInts(view.HopChannels))
		case "access-point":
			where = fmt.Sprintf("channel %d, sharing the lab access point's radio", view.Channel)
		}
		c.printf("Wi-Fi visibility  %s with %s (%s)\n", c.style(styleGreen, "listening"), sanitize(view.Adapter), where)
	case view.Settings.Enabled:
		c.printf("Wi-Fi visibility  %s\n", c.style(styleYellow, "on, but not running"))
	default:
		c.printf("Wi-Fi visibility  %s\n", c.style(styleYellow, "off"))
	}
	if !view.Available && view.Reason != "" {
		c.printf("  %s %s\n", c.style(styleYellow, "!"), sanitize(view.Reason))
	}
	if view.LastError != "" && !view.Active {
		c.printf("  %s last attempt: %s\n", c.style(styleYellow, "!"), sanitize(view.LastError))
	}
	if view.Active && (!view.Capturing || !view.WorkerRunning) {
		c.printf("  %s capture running: %v, frame worker running: %v\n", c.style(styleYellow, "!"), view.Capturing, view.WorkerRunning)
	}
	nearby := "only lab devices and the lab network are recorded"
	if view.Settings.Nearby {
		nearby = fmt.Sprintf("nearby devices and networks are recorded too (kept %d hours)", view.NearbyRetentionHours)
	}
	c.printf("Recording scope   %s; %d lab device addresses known", nearby, view.LabDevices)
	if view.LabSSID != "" {
		c.printf(", lab network %q", sanitize(view.LabSSID))
	}
	c.printf("\n")
	if len(view.Adapters) == 0 {
		c.printf("Adapters          none (plug in a USB Wi-Fi adapter that supports monitor mode)\n")
	}
	for index, adapter := range view.Adapters {
		label := "Adapters         "
		if index > 0 {
			label = "                 "
		}
		traits := []string{}
		if adapter.MonitorSupported {
			traits = append(traits, "monitor mode")
		} else {
			traits = append(traits, "no monitor mode")
		}
		if adapter.AccessPoint {
			traits = append(traits, "lab access point")
		}
		if adapter.InUse {
			traits = append(traits, "carries this host's connection")
		}
		if len(adapter.Bands) > 0 {
			traits = append(traits, strings.Join(adapter.Bands, "/"))
		}
		c.printf("%s %s: %s\n", label, sanitize(adapter.Interface), strings.Join(traits, ", "))
	}
	for _, note := range view.Notes {
		c.printf("  %s %s\n", c.dim("•"), sanitize(note))
	}
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(value)
	}
	return strings.Join(parts, ", ")
}
