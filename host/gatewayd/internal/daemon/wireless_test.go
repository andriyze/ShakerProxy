package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const iwPhyInfoWithAP = `Wiphy phy0
	wiphy index: 0
	max # scan SSIDs: 4
	Supported Ciphers:
		* WEP40 (00-0f-ac:1)
		* CCMP-128 (00-0f-ac:4)
	Available Antennas: TX 0x3 RX 0x3
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
		 * AP/VLAN
		 * monitor
		 * mesh point
	Band 1:
		Capabilities: 0x1ff
		Bitrates (non-HT):
			* 1.0 Mbps
			* 2.0 Mbps (short preamble supported)
		Frequencies:
			* 2412.0 MHz [1] (20.0 dBm)
			* 2467.0 MHz [12] (20.0 dBm) (no IR)
			* 2484.0 MHz [14] (disabled)
	Band 2:
		Frequencies:
			* 5180 MHz [36] (23.0 dBm) (no IR)
			* 5260 MHz [52] (20.0 dBm) (no IR, radar detection)
	Band 4:
		Frequencies:
			* 5955 MHz [1] (disabled)
	valid interface combinations:
		 * #{ managed } <= 1, #{ AP, P2P-client, P2P-GO } <= 1,
		   total <= 3, #channels <= 2
	software interface modes (can always be added):
		 * AP/VLAN
		 * monitor
`

const iwPhyInfoWithoutAP = `Wiphy phy1
	Supported interface modes:
		 * managed
		 * AP/VLAN
		 * monitor
	Band 1:
		Frequencies:
			* 2412 MHz [1] (20.0 dBm)
	software interface modes (can always be added):
		 * AP
`

func TestParseIWPhyInfo(t *testing.T) {
	result := parseIWPhyInfo(iwPhyInfoWithAP)
	if !result.known || !result.apSupported || !reflect.DeepEqual(result.bands, []string{"2.4GHZ", "5GHZ"}) {
		t.Fatalf("AP-capable adapter parsed incorrectly: %+v", result)
	}
	result = parseIWPhyInfo(iwPhyInfoWithoutAP)
	if !result.known || result.apSupported || !reflect.DeepEqual(result.bands, []string{"2.4GHZ"}) {
		t.Fatalf("software AP/VLAN mode was mistaken for AP support: %+v", result)
	}
	if result := parseIWPhyInfo("command failed\n"); result.known || result.apSupported {
		t.Fatalf("unparseable output must be unknown: %+v", result)
	}
	if result := parseIWPhyInfo("\tSupported interface modes:\n\t\t * " + strings.Repeat("A", 5000) + "\n"); result.known {
		t.Fatalf("oversized line must make the result unknown: %+v", result)
	}
}

func wirelessSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, phy := range map[string]string{"wlan0": "phy0", "wlan1": "phy0", "wlan2": "../../x", "wlan3": ""} {
		if err := os.MkdirAll(filepath.Join(root, name, "phy80211"), 0o755); err != nil {
			t.Fatal(err)
		}
		if phy != "" {
			if err := os.WriteFile(filepath.Join(root, name, "phy80211", "name"), []byte(phy+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "enp1s0"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestWirelessInspectorReportsContractFields(t *testing.T) {
	calls := []string{}
	inspector := &wirelessInspector{sysfsRoot: wirelessSysfs(t), phyCache: map[string]phyCapabilities{}, runIW: func(_ context.Context, phy string) (string, error) {
		calls = append(calls, phy)
		return iwPhyInfoWithAP, nil
	}}
	wireless, ap, bands := inspector.inspect(context.Background(), "wlan0")
	if !wireless || ap == nil || !*ap || !reflect.DeepEqual(bands, []string{"2.4GHZ", "5GHZ"}) {
		t.Fatalf("wireless adapter misreported: %v %v %v", wireless, ap, bands)
	}
	if wireless, ap, _ := inspector.inspect(context.Background(), "wlan1"); !wireless || ap == nil || !*ap || len(calls) != 1 {
		t.Fatalf("shared phy was not inspected once: %v %v %v", wireless, ap, calls)
	}
	wireless, ap, bands = inspector.inspect(context.Background(), "enp1s0")
	if wireless || ap == nil || *ap || bands == nil || len(bands) != 0 {
		t.Fatalf("wired interface misreported: %v %v %v", wireless, ap, bands)
	}
	for _, name := range []string{"wlan2", "wlan3"} {
		if wireless, ap, bands := inspector.inspect(context.Background(), name); !wireless || ap != nil || len(bands) != 0 {
			t.Fatalf("%s with unusable phy evidence must be wireless with unknown AP support: %v %v %v", name, wireless, ap, bands)
		}
	}
	for _, name := range []string{"../wlan0", "wlan0 info", ".."} {
		if wireless, ap, _ := inspector.inspect(context.Background(), name); wireless || ap != nil {
			t.Fatalf("unsafe name %q reached sysfs", name)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("unexpected iw invocations: %v", calls)
	}

	failing := &wirelessInspector{sysfsRoot: wirelessSysfs(t), phyCache: map[string]phyCapabilities{}, runIW: func(context.Context, string) (string, error) {
		return "", errors.New("iw is not installed")
	}}
	if wireless, ap, bands := failing.inspect(context.Background(), "wlan0"); !wireless || ap != nil || len(bands) != 0 {
		t.Fatalf("missing iw must leave AP support unknown: %v %v %v", wireless, ap, bands)
	}
}

func TestWirelessCommandAllowlistIsExact(t *testing.T) {
	if !allowedWirelessCommand("/usr/sbin/iw", []string{"phy", "phy0", "info"}) || !allowedWirelessCommand("/usr/bin/systemctl", []string{"is-active", "NetworkManager.service"}) {
		t.Fatal("exact wireless inspection command rejected")
	}
	for _, rejected := range []struct {
		path string
		args []string
	}{
		{"/usr/sbin/iw", []string{"phy", "phy0", "set", "name", "x"}},
		{"/usr/sbin/iw", []string{"phy", "phy0;reboot", "info"}},
		{"/usr/sbin/iw", []string{"phy", "wlan0", "info"}},
		{"/usr/sbin/iw", []string{"dev", "wlan0", "info"}},
		{"/usr/sbin/iw", []string{"dev", "wlan0", "set", "type", "__ap"}},
		{"/sbin/iw", []string{"phy", "phy0", "info"}},
		{"/usr/bin/systemctl", []string{"stop", "NetworkManager.service"}},
		{"/usr/bin/systemctl", []string{"is-active", "shakerproxy-gatewayd.service"}},
		{"/bin/sh", []string{"-c", "iw phy phy0 info"}},
	} {
		if allowedWirelessCommand(rejected.path, rejected.args) {
			t.Fatalf("broad wireless command allowlisted: %s %q", rejected.path, rejected.args)
		}
	}
	if _, err := runWirelessCommand(context.Background(), "/usr/sbin/iw", []string{"dev"}); err == nil {
		t.Fatal("unlisted wireless command reached exec")
	}
}

func testWiFiPlan(bridged bool) networkplan.Plan {
	plan := networkplan.Plan{Schema: 1, Topology: networkplan.TopologyTwoNIC, Interfaces: []networkplan.Interface{
		{StableID: "wan", CurrentName: "eth0", Role: networkplan.RoleWAN},
		{StableID: "wifi", CurrentName: "wlan0", Role: networkplan.RoleWiFiAP},
	}, WiFi: &networkplan.WiFiConfiguration{Enabled: true, SSID: "ShakerProxy", BridgeWithLab: bridged}}
	if bridged {
		plan.Interfaces = append(plan.Interfaces, networkplan.Interface{StableID: "lab", CurrentName: "eth1", Role: networkplan.RoleLab})
	}
	return plan
}

func TestWiFiHostEvidenceQueriesOnlyWhatThePlanNeeds(t *testing.T) {
	yes := true
	host := gatewayprotocol.HostInspection{Interfaces: []gatewayprotocol.Interface{{Name: "wlan0", Wireless: true, APSupported: &yes, WirelessBands: []string{"2.4GHZ"}, DefaultIPv6: true}}}
	hostapdChecks, managerChecks := 0, 0
	hostapd := func() bool { hostapdChecks++; return true }
	manager := func(context.Context) bool { managerChecks++; return true }

	evidence := wifiHostEvidence(context.Background(), networkplan.Plan{}, host, hostapd, manager)
	if hostapdChecks != 0 || managerChecks != 0 || len(evidence.Interfaces) != 0 {
		t.Fatalf("wired plan inspected Wi-Fi host state: %+v", evidence)
	}
	evidence = wifiHostEvidence(context.Background(), testWiFiPlan(false), host, hostapd, manager)
	if hostapdChecks != 1 || managerChecks != 0 || !evidence.HostapdInstalled || evidence.NetworkManagerActive {
		t.Fatalf("Wi-Fi-only plan evidence is wrong: %+v", evidence)
	}
	if got := evidence.Interfaces["wlan0"]; !got.Wireless || got.APSupported == nil || !*got.APSupported || !got.DefaultRoute || !reflect.DeepEqual(got.Bands, []networkplan.WiFiBand{networkplan.WiFiBand24GHz}) {
		t.Fatalf("interface evidence was not converted: %+v", got)
	}
	evidence = wifiHostEvidence(context.Background(), testWiFiPlan(true), host, hostapd, manager)
	if managerChecks != 1 || !evidence.NetworkManagerActive {
		t.Fatalf("bridged plan did not check NetworkManager: %+v", evidence)
	}
}

func TestLabIngressMatchesBridgeByNameAndPortsByIdentity(t *testing.T) {
	bridge, _ := networkplan.LabInterface(testWiFiPlan(true))
	if !labIngressMatches(bridge, gatewayprotocol.Interface{Name: "lgbr0", StableID: "path:virtual:lgbr0|mac:02:00:00:00:00:01"}) {
		t.Fatal("observed ShakerProxy bridge was not matched")
	}
	if labIngressMatches(bridge, gatewayprotocol.Interface{Name: "eth1", StableID: bridge.StableID}) {
		t.Fatal("a physical interface impersonated the lab bridge")
	}
	ap, _ := networkplan.LabInterface(testWiFiPlan(false))
	if !labIngressMatches(ap, gatewayprotocol.Interface{Name: "renamed", StableID: "wifi"}) || labIngressMatches(ap, gatewayprotocol.Interface{Name: "wlan0", StableID: "other"}) {
		t.Fatal("access point lab ingress must match by stable identity")
	}
}

type fakeAccessPointFinalizer struct {
	calls int
	err   error
}

func (f *fakeAccessPointFinalizer) EnsureAccessPointEnabled(context.Context) error {
	f.calls++
	return f.err
}

func TestFinalizeAccessPoint(t *testing.T) {
	if err := finalizeAccessPoint(context.Background(), nil, networkplan.Plan{}); err != nil {
		t.Fatalf("wired plan required an access point finalizer: %v", err)
	}
	if err := finalizeAccessPoint(context.Background(), nil, testWiFiPlan(false)); err == nil {
		t.Fatal("Wi-Fi plan confirmed without an access point finalizer")
	}
	finalizer := &fakeAccessPointFinalizer{}
	if err := finalizeAccessPoint(context.Background(), finalizer, testWiFiPlan(false)); err != nil || finalizer.calls != 1 {
		t.Fatalf("access point was not enabled: %v %d", err, finalizer.calls)
	}
}

func wifiCoordinatorFixture(t *testing.T) (NetworkCoordinator, networkplan.StagedPlan, *fakeCoordinatorWatchdog, *fakeAccessPointFinalizer) {
	t.Helper()
	coordinator, _, watchdog, _, _ := coordinatorFixture(t)
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	preview := networkplan.Preview{
		Validation:          networkplan.ValidationResult{Valid: true, PlanHash: stateTestPlanHash},
		FirewallBackend:     "iptables-nft",
		FirewallEnvironment: firewall.Inspection{SelectedBackend: "iptables-nft", IptablesPath: "/usr/sbin/iptables", ApplyReady: true},
		NetplanYAML:         "network:\n  version: 2\n",
		FirewallRestoreIPv4: "*filter\nCOMMIT\n",
	}
	staged, err := store.StageNetworkPlan(testWiFiPlan(true), preview, "wifi-coordinator-request", time.Unix(8000, 0).Add(-time.Second), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.Store = store
	coordinator.Files = networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	accessPoint := &fakeAccessPointFinalizer{}
	coordinator.AccessPoint = accessPoint
	return coordinator, staged, watchdog, accessPoint
}

func TestCoordinatorEnablesAccessPointOnlyAfterConfirmation(t *testing.T) {
	coordinator, staged, watchdog, accessPoint := wifiCoordinatorFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	if accessPoint.calls != 0 {
		t.Fatal("access point was enabled for boot before confirmation")
	}
	confirmed, err := coordinator.Confirm(context.Background(), staged.ApplyID, staged.PlanHash)
	if err != nil || confirmed.Transaction.Phase != networktransaction.PhaseConfirmed || accessPoint.calls != 1 || watchdog.disarms != 1 {
		t.Fatalf("confirmed access point was not enabled: err=%v calls=%d disarms=%d", err, accessPoint.calls, watchdog.disarms)
	}
	if _, err := coordinator.Confirm(context.Background(), staged.ApplyID, staged.PlanHash); err != nil || accessPoint.calls != 2 {
		t.Fatalf("idempotent confirmation did not re-ensure the access point: %v %d", err, accessPoint.calls)
	}
}

func TestCoordinatorKeepsWatchdogWhenAccessPointEnablementFails(t *testing.T) {
	coordinator, staged, watchdog, accessPoint := wifiCoordinatorFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	accessPoint.err = errors.New("enable failed")
	confirmed, err := coordinator.Confirm(context.Background(), staged.ApplyID, staged.PlanHash)
	if err == nil || !strings.Contains(err.Error(), "Wi-Fi access point boot enablement") || confirmed.Transaction.Phase != networktransaction.PhaseConfirmed {
		t.Fatalf("access point enablement failure was hidden: %v", err)
	}
	if watchdog.disarms != 0 {
		t.Fatal("watchdog was disarmed before the access point was enabled")
	}
}

func TestRecoveryEnsuresConfirmedAccessPoint(t *testing.T) {
	coordinator, staged, _, accessPoint := wifiCoordinatorFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	manifest, err := coordinator.Files.ReadManifest(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	confirmedAt := manifest.CreatedAt.Add(20 * time.Second)
	if _, err := coordinator.Files.Confirm(staged.ApplyID, staged.PlanHash, confirmedAt); err != nil {
		t.Fatal(err)
	}
	recovery := NetworkRecovery{Store: coordinator.Store, Files: coordinator.Files, Watchdog: &fakeRecoveryWatchdog{}, Rollback: &fakeCoordinatorRollback{}, Finalizer: coordinator.Finalizer, AccessPoint: accessPoint, Now: func() time.Time { return confirmedAt.Add(time.Second) }}
	if err := recovery.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if accessPoint.calls != 1 {
		t.Fatalf("recovery did not ensure the confirmed access point: %d", accessPoint.calls)
	}
}

func TestWirelessDiagnosticOnlyForConfirmedWiFiPlans(t *testing.T) {
	if _, ok := wirelessDiagnostic(context.Background(), persistedState{OperatingMode: gatewayprotocol.ModeRouted}); ok {
		t.Fatal("diagnostic reported Wi-Fi without a confirmed plan")
	}
	record := networktransaction.Record{Phase: networktransaction.PhaseConfirmed}
	wired := persistedState{OperatingMode: gatewayprotocol.ModeRouted, StagedNetworkPlan: &networkplan.StagedPlan{Plan: networkplan.Plan{}, Transaction: &record}}
	if _, ok := wirelessDiagnostic(context.Background(), wired); ok {
		t.Fatal("diagnostic reported Wi-Fi for a wired plan")
	}
}
