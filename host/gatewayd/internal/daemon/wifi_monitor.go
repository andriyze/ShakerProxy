package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/wifi"
)

// Wi-Fi visibility. With an adapter that supports monitor mode, gatewayd
// adds a monitor interface (spmon0), tunes it, and starts dumpcap
// (shakerproxy-wifi-capture.service) and the unprivileged frame parser
// (shakerproxy-wifi-worker.service). The monitor only listens: nothing here
// transmits, injects or deauthenticates.

const (
	WiFiMonitorInterface           = "spmon0"
	wifiCaptureUnit                = "shakerproxy-wifi-capture.service"
	wifiWorkerUnit                 = "shakerproxy-wifi-worker.service"
	DefaultWiFiMonitorSettingsPath = "/var/lib/shakerproxy/gatewayd/wifi-monitor.json"
	wifiHopDwell                   = 500 * time.Millisecond
	wifiKeepInterval               = 15 * time.Second
	wifiRetryInterval              = time.Minute
	maxWiFiSettingsBytes           = 64 << 10
	maxWiFiAdapters                = 16
)

// gentleHopChannels are the non-overlapping 2.4 GHz channels and the common
// non-DFS 5 GHz channels: where nearly all networks and probes are.
var gentleHopChannels = []int{1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161}

var wifiPhyLine = regexp.MustCompile(`^phy[0-9]{1,4}$`)

// wifiHost is everything the monitor does to the host, so it can be tested
// without radios.
type wifiHost interface {
	// Wireless lists the host's wireless interfaces.
	Wireless(ctx context.Context) ([]wifiInterface, error)
	PhyInfo(ctx context.Context, phy string) (string, error)
	AddMonitor(ctx context.Context, phy string) error
	DeleteMonitor(ctx context.Context) error
	MonitorExists() bool
	LinkUp(name string) (bool, error)
	SetLinkUp(name string, up bool) error
	SetFrequency(ctx context.Context, frequency int) error
	StartUnit(ctx context.Context, unit string) error
	StopUnit(ctx context.Context, unit string) error
	UnitActive(ctx context.Context, unit string) bool
	WriteScope(path string, data []byte) error
}

type wifiInterface struct {
	Name    string
	Phy     string
	Address string
	// InUse: global addresses or a default route.
	InUse bool
}

type wifiPhyInfo struct {
	known           bool
	monitor         bool
	monitorSoftware bool
	frequencies     []int
}

// parseIWMonitorInfo reads monitor support and the enabled channels from
// `iw phy <phy> info`.
func parseIWMonitorInfo(output string) wifiPhyInfo {
	info := wifiPhyInfo{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 4096), 4096)
	section, sectionIndent := "", 0
	seen := map[int]bool{}
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, "*") {
			switch {
			case trimmed == "Supported interface modes:":
				section, sectionIndent, info.known = "modes", indent, true
			case strings.HasPrefix(trimmed, "software interface modes"):
				section, sectionIndent = "software", indent
			default:
				if section != "" && indent <= sectionIndent {
					section = ""
				}
			}
			continue
		}
		if section != "" && indent <= sectionIndent {
			section = ""
		}
		if !strings.HasPrefix(trimmed, "* ") {
			continue
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "* "))
		switch section {
		case "modes":
			if item == "monitor" {
				info.monitor = true
			}
			continue
		case "software":
			if item == "monitor" {
				info.monitorSoftware = true
			}
			continue
		}
		fields := strings.Fields(item)
		if len(fields) < 2 || fields[1] != "MHz" || strings.Contains(item, "(disabled)") {
			continue
		}
		frequency, err := strconv.ParseFloat(fields[0], 64)
		if err != nil || wifi.ChannelForFrequency(int(frequency)) == 0 || seen[int(frequency)] {
			continue
		}
		seen[int(frequency)] = true
		info.frequencies = append(info.frequencies, int(frequency))
	}
	if scanner.Err() != nil {
		return wifiPhyInfo{}
	}
	sort.Ints(info.frequencies)
	return info
}

// hopChannels picks the channels to hop over: the common ones the adapter
// supports, else every supported 2.4/5 GHz channel (at most 24).
func hopChannels(frequencies []int) []int {
	supported := map[int]bool{}
	all := []int{}
	for _, frequency := range frequencies {
		if wifi.Band(frequency) == "6GHz" {
			continue
		}
		channel := wifi.ChannelForFrequency(frequency)
		supported[channel] = true
		all = append(all, channel)
	}
	channels := []int{}
	for _, channel := range gentleHopChannels {
		if supported[channel] {
			channels = append(channels, channel)
		}
	}
	if len(channels) == 0 {
		channels = all
	}
	if len(channels) > 24 {
		channels = channels[:24]
	}
	return channels
}

// wifiMonitorDocument is the durable settings file. AdapterWasUp records
// that ShakerProxy took an idle adapter down to listen with it, so it is
// brought back up when monitoring stops, even after a restart.
type wifiMonitorDocument struct {
	Schema       int                                 `json:"schema"`
	Settings     gatewayprotocol.WiFiMonitorSettings `json:"settings"`
	Adapter      string                              `json:"adapter,omitempty"`
	AdapterWasUp bool                                `json:"adapter_was_up,omitempty"`
	UpdatedAt    time.Time                           `json:"updated_at"`
}

// WiFiMonitor owns the monitor interface, its capture and its scope.
type WiFiMonitor struct {
	SettingsPath string
	ScopePath    string
	Host         wifiHost
	// Plan returns the confirmed lab plan, if any.
	Plan func() (networkplan.Plan, bool)
	// LabMACs returns the hardware addresses of lab devices.
	LabMACs func(context.Context) []string
	Logger  *slog.Logger
	Now     func() time.Time

	mu           sync.Mutex
	document     wifiMonitorDocument
	loaded       bool
	active       bool
	adapter      string
	phy          string
	shared       bool
	channelMode  string
	frequency    int
	hops         []int
	hopCancel    context.CancelFunc
	lastError    string
	lastAttempt  time.Time
	scopeWritten []byte
}

func (m *WiFiMonitor) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func defaultWiFiSettings() gatewayprotocol.WiFiMonitorSettings {
	return gatewayprotocol.WiFiMonitorSettings{ChannelMode: gatewayprotocol.WiFiChannelAuto}
}

func (m *WiFiMonitor) load() {
	if m.loaded {
		return
	}
	m.loaded = true
	m.document = wifiMonitorDocument{Schema: 1, Settings: defaultWiFiSettings()}
	data, err := readBoundedFile(m.SettingsPath, maxWiFiSettingsBytes)
	if err != nil {
		return
	}
	var document wifiMonitorDocument
	if json.Unmarshal(data, &document) != nil || document.Schema != 1 || document.Settings.Validate() != nil {
		if m.Logger != nil {
			m.Logger.Warn("Wi-Fi monitor settings are invalid; monitoring stays off", "path", m.SettingsPath)
		}
		return
	}
	m.document = document
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds its bound")
	}
	return data, nil
}

func (m *WiFiMonitor) save() error {
	m.document.Schema = 1
	m.document.UpdatedAt = m.now()
	data, err := json.MarshalIndent(m.document, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.SettingsPath), 0o750); err != nil {
		return err
	}
	temporary := m.SettingsPath + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, m.SettingsPath)
}

type wifiAccessPoint struct {
	adapter string
	ssid    string
	channel int
}

func (m *WiFiMonitor) accessPoint() (wifiAccessPoint, bool) {
	if m.Plan == nil {
		return wifiAccessPoint{}, false
	}
	plan, ok := m.Plan()
	if !ok {
		return wifiAccessPoint{}, false
	}
	ap, ok := networkplan.WiFiAccessPoint(plan)
	if !ok || plan.WiFi == nil {
		return wifiAccessPoint{}, false
	}
	return wifiAccessPoint{adapter: ap.CurrentName, ssid: plan.WiFi.SSID, channel: networkplan.EffectiveWiFiChannel(*plan.WiFi)}, true
}

// adapters inspects every wireless interface but the monitor itself.
func (m *WiFiMonitor) adapters(ctx context.Context) ([]gatewayprotocol.WiFiAdapter, map[string]wifiPhyInfo, error) {
	interfaces, err := m.Host.Wireless(ctx)
	if err != nil {
		return nil, nil, err
	}
	ap, hasAP := m.accessPoint()
	infos := map[string]wifiPhyInfo{}
	adapters := []gatewayprotocol.WiFiAdapter{}
	for _, iface := range interfaces {
		if iface.Name == WiFiMonitorInterface || len(adapters) >= maxWiFiAdapters {
			continue
		}
		adapter := gatewayprotocol.WiFiAdapter{Interface: iface.Name, Phy: iface.Phy, InUse: iface.InUse, AccessPoint: hasAP && iface.Name == ap.adapter, Bands: []string{}, Channels: []int{}}
		if wifiPhyLine.MatchString(iface.Phy) {
			info, cached := infos[iface.Phy]
			if !cached {
				if output, err := m.Host.PhyInfo(ctx, iface.Phy); err == nil {
					info = parseIWMonitorInfo(output)
				}
				infos[iface.Phy] = info
			}
			adapter.MonitorSupported = info.monitor
			adapter.MonitorAlongsideAP = info.monitorSoftware
			bands := map[string]bool{}
			for _, frequency := range info.frequencies {
				if band := wifi.Band(frequency); band != "" && !bands[band] {
					bands[band] = true
					adapter.Bands = append(adapter.Bands, band)
				}
				adapter.Channels = append(adapter.Channels, wifi.ChannelForFrequency(frequency))
			}
		}
		adapters = append(adapters, adapter)
	}
	sort.Slice(adapters, func(left, right int) bool { return adapters[left].Interface < adapters[right].Interface })
	return adapters, infos, nil
}

// usable reports whether the monitor may use the adapter, and why not.
func usableWiFiAdapter(adapter gatewayprotocol.WiFiAdapter) (bool, string) {
	switch {
	case !adapter.MonitorSupported:
		return false, fmt.Sprintf("Wi-Fi adapter %s does not support monitor mode.", adapter.Interface)
	case adapter.AccessPoint && !adapter.MonitorAlongsideAP:
		return false, fmt.Sprintf("%s serves the lab Wi-Fi and cannot listen at the same time. Add a second Wi-Fi adapter that supports monitor mode.", adapter.Interface)
	case !adapter.AccessPoint && adapter.InUse:
		return false, fmt.Sprintf("%s carries this host's own network connection; ShakerProxy will not take it over. Add a second Wi-Fi adapter, or disconnect %s first.", adapter.Interface, adapter.Interface)
	}
	return true, ""
}

// chooseWiFiAdapter picks the adapter to listen with: the one asked for, or
// a free adapter, or the lab access point's when it can add a monitor.
func chooseWiFiAdapter(adapters []gatewayprotocol.WiFiAdapter, wanted string) (gatewayprotocol.WiFiAdapter, string) {
	if len(adapters) == 0 {
		return gatewayprotocol.WiFiAdapter{}, "No Wi-Fi adapter is connected. Plug in a USB Wi-Fi adapter that supports monitor mode (see the Wi-Fi visibility guide)."
	}
	if wanted != "" {
		for _, adapter := range adapters {
			if adapter.Interface == wanted {
				if ok, reason := usableWiFiAdapter(adapter); !ok {
					return gatewayprotocol.WiFiAdapter{}, reason
				}
				return adapter, ""
			}
		}
		return gatewayprotocol.WiFiAdapter{}, fmt.Sprintf("Wi-Fi adapter %s is not connected.", wanted)
	}
	reason := ""
	for _, accessPoint := range []bool{false, true} {
		for _, adapter := range adapters {
			if adapter.AccessPoint != accessPoint {
				continue
			}
			ok, why := usableWiFiAdapter(adapter)
			if ok {
				return adapter, ""
			}
			if reason == "" {
				reason = why
			}
		}
	}
	return gatewayprotocol.WiFiAdapter{}, reason
}

// Status reports the settings, the adapters and what runs.
func (m *WiFiMonitor) Status(ctx context.Context) gatewayprotocol.WiFiMonitorStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	return m.statusLocked(ctx)
}

func (m *WiFiMonitor) statusLocked(ctx context.Context) gatewayprotocol.WiFiMonitorStatus {
	status := gatewayprotocol.WiFiMonitorStatus{
		Schema: gatewayprotocol.WiFiMonitorSchema, Settings: m.document.Settings, Adapters: []gatewayprotocol.WiFiAdapter{},
		NearbyRetentionHours: gatewayprotocol.WiFiNearbyRetentionHours, LastError: m.lastError, CheckedAt: m.now(),
	}
	adapters, _, err := m.adapters(ctx)
	if err != nil {
		status.Reason = "Wi-Fi adapters could not be inspected: " + err.Error()
	} else {
		status.Adapters = adapters
		chosen, reason := chooseWiFiAdapter(adapters, m.document.Settings.Adapter)
		status.Available = chosen.Interface != ""
		status.Reason = reason
	}
	if ap, ok := m.accessPoint(); ok {
		status.LabSSID = ap.ssid
	}
	if m.LabMACs != nil {
		status.LabDevices = len(m.LabMACs(ctx))
	}
	if m.active {
		status.Interface, status.Adapter, status.Phy = WiFiMonitorInterface, m.adapter, m.phy
		status.SharedWithAccessPoint = m.shared
		status.ChannelMode, status.FrequencyMHz = m.channelMode, m.frequency
		status.Channel = wifi.ChannelForFrequency(m.frequency)
		status.HopChannels = append([]int(nil), m.hops...)
		status.Capturing = m.Host.UnitActive(ctx, wifiCaptureUnit)
		status.WorkerRunning = m.Host.UnitActive(ctx, wifiWorkerUnit)
		status.Active = m.Host.MonitorExists() && status.Capturing
	}
	return status
}

// Set changes the settings and applies them. Turning monitoring on fails,
// and leaves it off, when no adapter can listen.
func (m *WiFiMonitor) Set(ctx context.Context, params gatewayprotocol.SetWiFiMonitorParams) (gatewayprotocol.WiFiMonitorStatus, error) {
	if err := params.Settings.Validate(); err != nil {
		return gatewayprotocol.WiFiMonitorStatus{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	if params.Settings.Nearby && !m.document.Settings.Nearby && !params.AcknowledgeNearby {
		return gatewayprotocol.WiFiMonitorStatus{}, errors.New("recording nearby devices and networks records people who are not part of the test; confirm it (acknowledge_nearby)")
	}
	previous := m.document.Settings
	m.document.Settings = params.Settings
	m.stopLocked(ctx)
	if params.Settings.Enabled {
		if err := m.startLocked(ctx); err != nil {
			m.document.Settings = previous
			m.document.Settings.Enabled = false
			_ = m.save()
			return m.statusLocked(ctx), err
		}
	}
	if err := m.save(); err != nil {
		return m.statusLocked(ctx), fmt.Errorf("save Wi-Fi monitor settings: %w", err)
	}
	if m.Logger != nil {
		m.Logger.Info("Wi-Fi monitor settings changed", "enabled", params.Settings.Enabled, "channel_mode", params.Settings.ChannelMode, "channel", params.Settings.Channel, "nearby", params.Settings.Nearby, "adapter", m.adapter)
	}
	return m.statusLocked(ctx), nil
}

// startLocked adds the monitor interface, tunes it, writes the scope and
// starts the capture and the worker. Any failure undoes what was done.
func (m *WiFiMonitor) startLocked(ctx context.Context) (err error) {
	m.lastAttempt = m.now()
	adapters, infos, inspectErr := m.adapters(ctx)
	if inspectErr != nil {
		return m.fail(fmt.Errorf("Wi-Fi adapters could not be inspected: %w", inspectErr))
	}
	chosen, reason := chooseWiFiAdapter(adapters, m.document.Settings.Adapter)
	if chosen.Interface == "" {
		return m.fail(errors.New(reason))
	}
	info := infos[chosen.Phy]
	ap, hasAP := m.accessPoint()
	m.adapter, m.phy, m.shared = chosen.Interface, chosen.Phy, chosen.AccessPoint
	var undo []func()
	defer func() {
		if err == nil {
			return
		}
		for index := len(undo) - 1; index >= 0; index-- {
			undo[index]()
		}
		m.active = false
	}()
	if m.Host.MonitorExists() {
		if deleteErr := m.Host.DeleteMonitor(ctx); deleteErr != nil {
			return m.fail(fmt.Errorf("remove the old monitor interface: %w", deleteErr))
		}
	}
	if !chosen.AccessPoint {
		// An idle adapter is taken down so its radio is free to listen; it
		// comes back up when monitoring stops.
		up, upErr := m.Host.LinkUp(chosen.Interface)
		if upErr == nil && up {
			if downErr := m.Host.SetLinkUp(chosen.Interface, false); downErr != nil {
				return m.fail(fmt.Errorf("take %s down: %w", chosen.Interface, downErr))
			}
			m.document.Adapter, m.document.AdapterWasUp = chosen.Interface, true
			undo = append(undo, func() {
				_ = m.Host.SetLinkUp(chosen.Interface, true)
				m.document.AdapterWasUp = false
			})
		}
	}
	if addErr := m.Host.AddMonitor(ctx, chosen.Phy); addErr != nil {
		return m.fail(fmt.Errorf("add a monitor interface to %s: %w", chosen.Interface, addErr))
	}
	undo = append(undo, func() { _ = m.Host.DeleteMonitor(context.Background()) })
	if upErr := m.Host.SetLinkUp(WiFiMonitorInterface, true); upErr != nil {
		return m.fail(fmt.Errorf("bring the monitor interface up: %w", upErr))
	}
	m.hops, m.frequency = nil, 0
	switch {
	case chosen.AccessPoint:
		m.channelMode = gatewayprotocol.WiFiChannelAccessPoint
		if hasAP {
			m.frequency = wifi.FrequencyForChannel(ap.channel)
		}
	case m.document.Settings.ChannelMode == gatewayprotocol.WiFiChannelFixed:
		m.channelMode = gatewayprotocol.WiFiChannelFixed
		m.frequency = wifi.FrequencyForChannel(m.document.Settings.Channel)
	case m.document.Settings.ChannelMode == gatewayprotocol.WiFiChannelAuto && hasAP:
		// The lab access point runs on another adapter: listen on its
		// channel, where the lab devices are.
		m.channelMode = gatewayprotocol.WiFiChannelFixed
		m.frequency = wifi.FrequencyForChannel(ap.channel)
	default:
		m.channelMode = gatewayprotocol.WiFiChannelHop
		m.hops = hopChannels(info.frequencies)
		if len(m.hops) == 0 {
			return m.fail(fmt.Errorf("%s reports no usable channels", chosen.Interface))
		}
		m.frequency = wifi.FrequencyForChannel(m.hops[0])
	}
	if !chosen.AccessPoint && m.frequency != 0 {
		if !supportsFrequency(info.frequencies, m.frequency) {
			return m.fail(fmt.Errorf("%s cannot listen on channel %d", chosen.Interface, wifi.ChannelForFrequency(m.frequency)))
		}
		if tuneErr := m.Host.SetFrequency(ctx, m.frequency); tuneErr != nil {
			return m.fail(fmt.Errorf("tune the monitor to channel %d: %w", wifi.ChannelForFrequency(m.frequency), tuneErr))
		}
	}
	if scopeErr := m.writeScopeLocked(ctx); scopeErr != nil {
		return m.fail(fmt.Errorf("write the Wi-Fi recording scope: %w", scopeErr))
	}
	if startErr := m.Host.StartUnit(ctx, wifiWorkerUnit); startErr != nil {
		return m.fail(fmt.Errorf("start the Wi-Fi worker: %w", startErr))
	}
	undo = append(undo, func() { _ = m.Host.StopUnit(context.Background(), wifiWorkerUnit) })
	if startErr := m.Host.StartUnit(ctx, wifiCaptureUnit); startErr != nil {
		return m.fail(fmt.Errorf("start the Wi-Fi capture: %w", startErr))
	}
	m.active, m.lastError = true, ""
	if len(m.hops) > 1 {
		hopContext, cancel := context.WithCancel(context.Background())
		m.hopCancel = cancel
		go m.hop(hopContext, append([]int(nil), m.hops...))
	}
	if m.Logger != nil {
		m.Logger.Info("Wi-Fi monitor started", "adapter", chosen.Interface, "phy", chosen.Phy, "channel_mode", m.channelMode, "channel", wifi.ChannelForFrequency(m.frequency), "shared_with_access_point", chosen.AccessPoint)
	}
	return nil
}

func supportsFrequency(frequencies []int, frequency int) bool {
	for _, value := range frequencies {
		if value == frequency {
			return true
		}
	}
	return false
}

func (m *WiFiMonitor) fail(err error) error {
	m.lastError = err.Error()
	if m.Logger != nil {
		m.Logger.Warn("Wi-Fi monitor could not start", "error", err)
	}
	return err
}

// stopLocked stops the capture and the worker, removes the monitor
// interface and brings a borrowed adapter back up.
func (m *WiFiMonitor) stopLocked(ctx context.Context) {
	if m.hopCancel != nil {
		m.hopCancel()
		m.hopCancel = nil
	}
	_ = m.Host.StopUnit(ctx, wifiCaptureUnit)
	_ = m.Host.StopUnit(ctx, wifiWorkerUnit)
	if m.Host.MonitorExists() {
		if err := m.Host.DeleteMonitor(ctx); err != nil && m.Logger != nil {
			m.Logger.Warn("Wi-Fi monitor interface could not be removed", "error", err)
		}
	}
	if m.document.AdapterWasUp && m.document.Adapter != "" {
		if err := m.Host.SetLinkUp(m.document.Adapter, true); err != nil && m.Logger != nil {
			m.Logger.Warn("Wi-Fi adapter could not be brought back up", "adapter", m.document.Adapter, "error", err)
		}
		m.document.AdapterWasUp = false
	}
	m.active, m.hops, m.frequency, m.channelMode = false, nil, 0, ""
}

// hop moves the monitor across channels until ctx ends.
func (m *WiFiMonitor) hop(ctx context.Context, channels []int) {
	ticker := time.NewTicker(wifiHopDwell)
	defer ticker.Stop()
	index, failures := 0, 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		index = (index + 1) % len(channels)
		frequency := wifi.FrequencyForChannel(channels[index])
		tuneContext, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := m.Host.SetFrequency(tuneContext, frequency)
		cancel()
		if err != nil {
			failures++
			if failures == 1 && m.Logger != nil {
				m.Logger.Warn("Wi-Fi monitor could not change channel", "channel", channels[index], "error", err)
			}
			continue
		}
		failures = 0
		m.mu.Lock()
		if m.active {
			m.frequency = frequency
		}
		m.mu.Unlock()
	}
}

// writeScopeLocked tells the worker what it may record: the lab access
// point, the lab SSID, the lab devices' addresses and the nearby opt-in.
func (m *WiFiMonitor) writeScopeLocked(ctx context.Context) error {
	scope := wifi.ScopeFile{Schema: wifi.ScopeSchema, LabBSSIDs: []string{}, LabSSIDs: []string{}, LabMACs: []string{}, Nearby: m.document.Settings.Nearby, GeneratedAt: m.now()}
	if ap, ok := m.accessPoint(); ok {
		if ap.ssid != "" {
			scope.LabSSIDs = append(scope.LabSSIDs, ap.ssid)
		}
		if interfaces, err := m.Host.Wireless(ctx); err == nil {
			for _, iface := range interfaces {
				if mac, valid := wifi.ParseMAC(iface.Address); iface.Name == ap.adapter && valid && !mac.Group() && !mac.Zero() {
					scope.LabBSSIDs = append(scope.LabBSSIDs, mac.String())
				}
			}
		}
	}
	if m.LabMACs != nil {
		seen := map[string]bool{}
		for _, value := range m.LabMACs(ctx) {
			mac, ok := wifi.ParseMAC(value)
			if !ok || mac.Group() || mac.Zero() || seen[mac.String()] || len(scope.LabMACs) >= wifi.MaxScopeMACs {
				continue
			}
			seen[mac.String()] = true
			scope.LabMACs = append(scope.LabMACs, mac.String())
		}
		sort.Strings(scope.LabMACs)
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	comparable := scope
	comparable.GeneratedAt = time.Time{}
	fingerprint, _ := json.Marshal(comparable)
	if string(fingerprint) == string(m.scopeWritten) {
		return nil
	}
	data, err := json.Marshal(scope)
	if err != nil {
		return err
	}
	if err := m.Host.WriteScope(m.ScopePath, data); err != nil {
		return err
	}
	m.scopeWritten = fingerprint
	return nil
}

// Keep re-establishes monitoring after a restart or an unplugged adapter,
// and keeps the scope current, until ctx ends.
func (m *WiFiMonitor) Keep(ctx context.Context) {
	m.mu.Lock()
	m.load()
	// A monitor left by an earlier run is rebuilt from the settings; a
	// host where monitoring was never on is not touched.
	if m.document.Settings.Enabled || m.document.AdapterWasUp || m.Host.MonitorExists() {
		m.stopLocked(ctx)
		_ = m.save()
	}
	m.mu.Unlock()
	ticker := time.NewTicker(wifiKeepInterval)
	defer ticker.Stop()
	for {
		m.keepOnce(ctx)
		select {
		case <-ctx.Done():
			m.mu.Lock()
			if m.hopCancel != nil {
				m.hopCancel()
				m.hopCancel = nil
			}
			m.mu.Unlock()
			return
		case <-ticker.C:
		}
	}
}

func (m *WiFiMonitor) keepOnce(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	if !m.document.Settings.Enabled {
		return
	}
	if m.active && m.Host.MonitorExists() && m.Host.UnitActive(ctx, wifiCaptureUnit) {
		if err := m.writeScopeLocked(ctx); err != nil && m.Logger != nil {
			m.Logger.Warn("Wi-Fi recording scope could not be refreshed", "error", err)
		}
		return
	}
	if !m.lastAttempt.IsZero() && m.now().Sub(m.lastAttempt) < wifiRetryInterval {
		return
	}
	m.stopLocked(ctx)
	if err := m.startLocked(ctx); err == nil {
		_ = m.save()
	}
}
