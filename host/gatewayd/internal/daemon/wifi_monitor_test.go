package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/wifi"
)

const iwPhyMonitorInfo = `Wiphy phy1
	max # scan SSIDs: 4
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
		 * AP/VLAN
		 * monitor
		 * mesh point
	Band 1:
		Frequencies:
			* 2412 MHz [1] (20.0 dBm)
			* 2437 MHz [6] (20.0 dBm)
			* 2462 MHz [11] (20.0 dBm)
			* 2467 MHz [12] (disabled)
	Band 2:
		Frequencies:
			* 5180 MHz [36] (23.0 dBm)
			* 5260 MHz [52] (20.0 dBm) (no IR, radar detection)
			* 5745 MHz [149] (30.0 dBm)
	software interface modes (can always be added):
		 * AP/VLAN
		 * monitor
	valid interface combinations:
		 * #{ managed } <= 1, #{ AP, mesh point } <= 1,
		   total <= 2, #channels <= 1
`

const iwPhyNoMonitorInfo = `Wiphy phy0
	Supported interface modes:
		 * managed
		 * AP
	Band 1:
		Frequencies:
			* 2412 MHz [1] (20.0 dBm)
`

type fakeWiFiHost struct {
	interfaces  []wifiInterface
	phyInfo     map[string]string
	monitor     bool
	links       map[string]bool
	frequencies []int
	units       map[string]bool
	scope       []byte
	calls       []string
	failAdd     error
	failUnit    string
}

func newFakeWiFiHost() *fakeWiFiHost {
	return &fakeWiFiHost{
		interfaces: []wifiInterface{
			{Name: "wlan0", Phy: "phy0", Address: "aa:bb:cc:00:00:01", InUse: true},
			{Name: "wlan1", Phy: "phy1", Address: "aa:bb:cc:00:00:02"},
		},
		phyInfo: map[string]string{"phy0": iwPhyNoMonitorInfo, "phy1": iwPhyMonitorInfo},
		links:   map[string]bool{"wlan0": true, "wlan1": true},
		units:   map[string]bool{},
	}
}

func (f *fakeWiFiHost) Wireless(context.Context) ([]wifiInterface, error) {
	return append([]wifiInterface(nil), f.interfaces...), nil
}
func (f *fakeWiFiHost) PhyInfo(_ context.Context, phy string) (string, error) {
	info, ok := f.phyInfo[phy]
	if !ok {
		return "", errors.New("no such phy")
	}
	return info, nil
}
func (f *fakeWiFiHost) AddMonitor(_ context.Context, phy string) error {
	f.calls = append(f.calls, "add "+phy)
	if f.failAdd != nil {
		return f.failAdd
	}
	f.monitor = true
	f.links[WiFiMonitorInterface] = false
	return nil
}
func (f *fakeWiFiHost) DeleteMonitor(context.Context) error {
	f.calls = append(f.calls, "del")
	f.monitor = false
	delete(f.links, WiFiMonitorInterface)
	return nil
}
func (f *fakeWiFiHost) MonitorExists() bool { return f.monitor }
func (f *fakeWiFiHost) LinkUp(name string) (bool, error) {
	up, ok := f.links[name]
	if !ok {
		return false, errors.New("no such interface")
	}
	return up, nil
}
func (f *fakeWiFiHost) SetLinkUp(name string, up bool) error {
	if _, ok := f.links[name]; !ok {
		return errors.New("no such interface")
	}
	f.links[name] = up
	return nil
}
func (f *fakeWiFiHost) SetFrequency(_ context.Context, frequency int) error {
	f.frequencies = append(f.frequencies, frequency)
	return nil
}
func (f *fakeWiFiHost) StartUnit(_ context.Context, unit string) error {
	f.calls = append(f.calls, "start "+unit)
	if unit == f.failUnit {
		return errors.New("unit failed")
	}
	f.units[unit] = true
	return nil
}
func (f *fakeWiFiHost) StopUnit(_ context.Context, unit string) error {
	f.units[unit] = false
	return nil
}
func (f *fakeWiFiHost) UnitActive(_ context.Context, unit string) bool { return f.units[unit] }
func (f *fakeWiFiHost) WriteScope(_ string, data []byte) error {
	f.scope = append([]byte(nil), data...)
	return nil
}

func testWiFiMonitor(t *testing.T, host *fakeWiFiHost, plan *networkplan.Plan) *WiFiMonitor {
	t.Helper()
	directory := t.TempDir()
	return &WiFiMonitor{
		SettingsPath: filepath.Join(directory, "wifi-monitor.json"),
		ScopePath:    filepath.Join(directory, "scope.json"),
		Host:         host,
		Plan: func() (networkplan.Plan, bool) {
			if plan == nil {
				return networkplan.Plan{}, false
			}
			return *plan, true
		},
		LabMACs: func(context.Context) []string {
			return []string{"3c:22:fb:00:00:10", "3C-22-FB-00-00-10", "bad", "01:00:5e:00:00:01"}
		},
		Now: func() time.Time { return time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) },
	}
}

func accessPointPlan(adapter string) *networkplan.Plan {
	return &networkplan.Plan{
		Interfaces: []networkplan.Interface{{CurrentName: adapter, Role: networkplan.RoleWiFiAP}},
		WiFi:       &networkplan.WiFiConfiguration{Enabled: true, SSID: "ShakerProxy-Lab", Channel: 11},
	}
}

func TestParseIWMonitorInfo(t *testing.T) {
	info := parseIWMonitorInfo(iwPhyMonitorInfo)
	if !info.known || !info.monitor || !info.monitorSoftware {
		t.Fatalf("info = %+v", info)
	}
	if want := []int{2412, 2437, 2462, 5180, 5260, 5745}; !reflect.DeepEqual(info.frequencies, want) {
		t.Fatalf("frequencies = %v, want %v", info.frequencies, want)
	}
	if want := []int{1, 6, 11, 36, 149}; !reflect.DeepEqual(hopChannels(info.frequencies), want) {
		t.Fatalf("hop channels = %v", hopChannels(info.frequencies))
	}
	plain := parseIWMonitorInfo(iwPhyNoMonitorInfo)
	if !plain.known || plain.monitor || plain.monitorSoftware {
		t.Fatalf("info without monitor = %+v", plain)
	}
}

func TestChooseWiFiAdapterExplainsWhy(t *testing.T) {
	if _, reason := chooseWiFiAdapter(nil, ""); !strings.Contains(reason, "No Wi-Fi adapter") {
		t.Fatalf("reason = %q", reason)
	}
	busy := gatewayprotocol.WiFiAdapter{Interface: "wlan0", MonitorSupported: true, InUse: true}
	if _, reason := chooseWiFiAdapter([]gatewayprotocol.WiFiAdapter{busy}, ""); !strings.Contains(reason, "will not take it over") {
		t.Fatalf("reason = %q", reason)
	}
	ap := gatewayprotocol.WiFiAdapter{Interface: "wlan0", MonitorSupported: true, AccessPoint: true, InUse: true}
	if _, reason := chooseWiFiAdapter([]gatewayprotocol.WiFiAdapter{ap}, ""); !strings.Contains(reason, "cannot listen at the same time") {
		t.Fatalf("reason = %q", reason)
	}
	ap.MonitorAlongsideAP = true
	free := gatewayprotocol.WiFiAdapter{Interface: "wlan1", MonitorSupported: true}
	if chosen, _ := chooseWiFiAdapter([]gatewayprotocol.WiFiAdapter{ap, free}, ""); chosen.Interface != "wlan1" {
		t.Fatalf("a free adapter should win over the access point's: %+v", chosen)
	}
	if chosen, _ := chooseWiFiAdapter([]gatewayprotocol.WiFiAdapter{ap}, ""); chosen.Interface != "wlan0" {
		t.Fatalf("the access point's adapter can listen alongside: %+v", chosen)
	}
	if _, reason := chooseWiFiAdapter([]gatewayprotocol.WiFiAdapter{free}, "wlan9"); !strings.Contains(reason, "not connected") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestWiFiMonitorStartsHoppingOnAFreeAdapterAndStopsCleanly(t *testing.T) {
	host := newFakeWiFiHost()
	monitor := testWiFiMonitor(t, host, nil)
	status, err := monitor.Set(context.Background(), gatewayprotocol.SetWiFiMonitorParams{Settings: gatewayprotocol.WiFiMonitorSettings{Enabled: true, ChannelMode: gatewayprotocol.WiFiChannelAuto}})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Active || status.Adapter != "wlan1" || status.ChannelMode != gatewayprotocol.WiFiChannelHop || !reflect.DeepEqual(status.HopChannels, []int{1, 6, 11, 36, 149}) {
		t.Fatalf("status = %+v", status)
	}
	if host.links["wlan1"] || !host.links[WiFiMonitorInterface] {
		t.Fatalf("links = %v", host.links)
	}
	if !host.units[wifiCaptureUnit] || !host.units[wifiWorkerUnit] {
		t.Fatalf("units = %v", host.units)
	}
	var scope wifi.ScopeFile
	if err := json.Unmarshal(host.scope, &scope); err != nil || scope.Validate() != nil {
		t.Fatalf("scope %s: %v", host.scope, err)
	}
	if !reflect.DeepEqual(scope.LabMACs, []string{"3c:22:fb:00:00:10"}) || len(scope.LabBSSIDs) != 0 || scope.Nearby {
		t.Fatalf("scope = %+v", scope)
	}
	status, err = monitor.Set(context.Background(), gatewayprotocol.SetWiFiMonitorParams{Settings: gatewayprotocol.WiFiMonitorSettings{ChannelMode: gatewayprotocol.WiFiChannelAuto}})
	if err != nil || status.Active {
		t.Fatalf("stop: %+v %v", status, err)
	}
	if host.monitor || !host.links["wlan1"] || host.units[wifiCaptureUnit] || host.units[wifiWorkerUnit] {
		t.Fatalf("not cleaned up: monitor=%v links=%v units=%v", host.monitor, host.links, host.units)
	}
}

func TestWiFiMonitorListensOnTheLabAccessPointsChannel(t *testing.T) {
	host := newFakeWiFiHost()
	host.interfaces[0].InUse = false
	monitor := testWiFiMonitor(t, host, accessPointPlan("wlan0"))
	status, err := monitor.Set(context.Background(), gatewayprotocol.SetWiFiMonitorParams{Settings: gatewayprotocol.WiFiMonitorSettings{Enabled: true, ChannelMode: gatewayprotocol.WiFiChannelAuto}})
	if err != nil {
		t.Fatal(err)
	}
	if status.Adapter != "wlan1" || status.Channel != 11 || status.ChannelMode != gatewayprotocol.WiFiChannelFixed || status.LabSSID != "ShakerProxy-Lab" {
		t.Fatalf("status = %+v", status)
	}
	var scope wifi.ScopeFile
	if err := json.Unmarshal(host.scope, &scope); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(scope.LabBSSIDs, []string{"aa:bb:cc:00:00:01"}) || !reflect.DeepEqual(scope.LabSSIDs, []string{"ShakerProxy-Lab"}) {
		t.Fatalf("scope = %+v", scope)
	}
}

func TestWiFiMonitorSharesTheAccessPointRadioWhenItMust(t *testing.T) {
	host := newFakeWiFiHost()
	host.interfaces = host.interfaces[1:]
	monitor := testWiFiMonitor(t, host, accessPointPlan("wlan1"))
	status, err := monitor.Set(context.Background(), gatewayprotocol.SetWiFiMonitorParams{Settings: gatewayprotocol.WiFiMonitorSettings{Enabled: true, ChannelMode: gatewayprotocol.WiFiChannelHop}})
	if err != nil {
		t.Fatal(err)
	}
	if !status.SharedWithAccessPoint || status.ChannelMode != gatewayprotocol.WiFiChannelAccessPoint || len(host.frequencies) != 0 || !host.links["wlan1"] {
		t.Fatalf("status = %+v frequencies %v links %v", status, host.frequencies, host.links)
	}
}

func TestWiFiMonitorRollsBackAFailedStart(t *testing.T) {
	host := newFakeWiFiHost()
	host.failUnit = wifiCaptureUnit
	monitor := testWiFiMonitor(t, host, nil)
	status, err := monitor.Set(context.Background(), gatewayprotocol.SetWiFiMonitorParams{Settings: gatewayprotocol.WiFiMonitorSettings{Enabled: true, ChannelMode: gatewayprotocol.WiFiChannelFixed, Channel: 6}})
	if err == nil || !strings.Contains(err.Error(), "Wi-Fi capture") {
		t.Fatalf("err = %v", err)
	}
	if host.monitor || !host.links["wlan1"] || host.units[wifiWorkerUnit] || status.Active || status.Settings.Enabled || status.LastError == "" {
		t.Fatalf("not rolled back: monitor=%v links=%v units=%v status=%+v", host.monitor, host.links, host.units, status)
	}
	reloaded := testWiFiMonitor(t, host, nil)
	reloaded.SettingsPath = monitor.SettingsPath
	if reloaded.Status(context.Background()).Settings.Enabled {
		t.Fatal("a failed start was saved as enabled")
	}
}

func TestWiFiMonitorRefusesUnusableAdaptersAndUnconfirmedNearby(t *testing.T) {
	host := newFakeWiFiHost()
	host.interfaces = host.interfaces[:1] // only the host's own connection
	monitor := testWiFiMonitor(t, host, nil)
	if _, err := monitor.Set(context.Background(), gatewayprotocol.SetWiFiMonitorParams{Settings: gatewayprotocol.WiFiMonitorSettings{Enabled: true, ChannelMode: gatewayprotocol.WiFiChannelAuto}}); err == nil {
		t.Fatal("started on an adapter without monitor mode")
	}
	if len(host.calls) != 0 {
		t.Fatalf("host was changed: %v", host.calls)
	}
	status := monitor.Status(context.Background())
	if status.Available || !strings.Contains(status.Reason, "monitor mode") {
		t.Fatalf("status = %+v", status)
	}
	if _, err := monitor.Set(context.Background(), gatewayprotocol.SetWiFiMonitorParams{Settings: gatewayprotocol.WiFiMonitorSettings{ChannelMode: gatewayprotocol.WiFiChannelAuto, Nearby: true}}); err == nil || !strings.Contains(err.Error(), "acknowledge_nearby") {
		t.Fatalf("nearby without confirmation: %v", err)
	}
	if _, err := monitor.Set(context.Background(), gatewayprotocol.SetWiFiMonitorParams{Settings: gatewayprotocol.WiFiMonitorSettings{ChannelMode: gatewayprotocol.WiFiChannelAuto, Nearby: true}, AcknowledgeNearby: true}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []gatewayprotocol.WiFiMonitorSettings{
		{ChannelMode: "sometimes"},
		{ChannelMode: gatewayprotocol.WiFiChannelFixed, Channel: 15},
		{ChannelMode: gatewayprotocol.WiFiChannelHop, Channel: 6},
		{ChannelMode: gatewayprotocol.WiFiChannelAuto, Adapter: "../wlan0"},
	} {
		if _, err := monitor.Set(context.Background(), gatewayprotocol.SetWiFiMonitorParams{Settings: bad}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestWiFiMonitorKeepRestoresMonitoringAfterRestart(t *testing.T) {
	host := newFakeWiFiHost()
	monitor := testWiFiMonitor(t, host, nil)
	if _, err := monitor.Set(context.Background(), gatewayprotocol.SetWiFiMonitorParams{Settings: gatewayprotocol.WiFiMonitorSettings{Enabled: true, ChannelMode: gatewayprotocol.WiFiChannelFixed, Channel: 36}}); err != nil {
		t.Fatal(err)
	}
	// gatewayd restarts: a new monitor reads the saved settings.
	restarted := testWiFiMonitor(t, host, nil)
	restarted.SettingsPath = monitor.SettingsPath
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { restarted.Keep(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		restarted.mu.Lock()
		active := restarted.active
		restarted.mu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("monitoring was not restored")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if host.frequencies[len(host.frequencies)-1] != 5180 || !host.monitor {
		t.Fatalf("frequencies %v monitor %v", host.frequencies, host.monitor)
	}
}

func TestWiFiMonitorCommandsAreAllowlisted(t *testing.T) {
	allowed := [][]string{
		{iwExecutable, "phy", "phy1", "interface", "add", WiFiMonitorInterface, "type", "monitor"},
		{iwExecutable, "dev", WiFiMonitorInterface, "del"},
		{iwExecutable, "dev", WiFiMonitorInterface, "set", "freq", "2437"},
		{systemctlExecutable, "start", wifiCaptureUnit},
		{systemctlExecutable, "is-active", "--quiet", wifiWorkerUnit},
	}
	for _, command := range allowed {
		if !allowedWiFiCommand(command[0], command[1:]) {
			t.Errorf("refused %v", command)
		}
	}
	refused := [][]string{
		{iwExecutable, "dev", "wlan0", "del"},
		{iwExecutable, "phy", "phy1", "interface", "add", "wlan9", "type", "monitor"},
		{iwExecutable, "dev", WiFiMonitorInterface, "set", "freq", "2400"},
		{iwExecutable, "dev", WiFiMonitorInterface, "set", "txpower", "fixed", "3000"},
		{systemctlExecutable, "start", "sshd.service"},
		{systemctlExecutable, "mask", wifiCaptureUnit},
		{"/bin/sh", "-c", "true"},
	}
	for _, command := range refused {
		if allowedWiFiCommand(command[0], command[1:]) {
			t.Errorf("allowed %v", command)
		}
	}
}
