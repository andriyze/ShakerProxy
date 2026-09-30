package networkapply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const testAccessPointPassphrase = "correct horse battery"

type fakeAccessPoint struct {
	starts       []AccessPointTarget
	disables     int
	startErr     error
	disableErr   error
	machine      *fakeApplyMachine
	dhcp4        *fakeDHCP4Service
	machineCalls int
	dhcp4Calls   int
}

func (f *fakeAccessPoint) StartAccessPoint(_ context.Context, target AccessPointTarget) error {
	f.starts = append(f.starts, target)
	if f.machine != nil {
		f.machineCalls = len(f.machine.calls)
	}
	if f.dhcp4 != nil {
		f.dhcp4Calls = len(f.dhcp4.calls)
	}
	return f.startErr
}

func (f *fakeAccessPoint) DisableAccessPoint(context.Context) error {
	f.disables++
	if f.dhcp4 != nil {
		f.dhcp4Calls = len(f.dhcp4.calls)
	}
	return f.disableErr
}

func wifiStagedPlan(t *testing.T, now time.Time, bridged bool) networkplan.StagedPlan {
	t.Helper()
	staged := validStagedPlan(t, now)
	staged.Plan.Interfaces = []networkplan.Interface{
		{StableID: "wan", CurrentName: "eth0", Role: networkplan.RoleWAN},
		{StableID: "wifi", CurrentName: "wlan0", Role: networkplan.RoleWiFiAP},
	}
	if bridged {
		staged.Plan.Interfaces = append(staged.Plan.Interfaces, networkplan.Interface{StableID: "lab", CurrentName: "eth1", Role: networkplan.RoleLab})
	}
	staged.Plan.WiFi = &networkplan.WiFiConfiguration{Enabled: true, SSID: "ShakerProxy", Security: networkplan.WiFiSecurityWPA2PSK, Passphrase: testAccessPointPassphrase, CountryCode: "US", BridgeWithLab: bridged}
	config, err := networkplan.RenderHostapdConf(staged.Plan)
	if err != nil {
		t.Fatal(err)
	}
	staged.Preview.HostapdConf = networkplan.RedactHostapdConf(config)
	return staged
}

func wifiApplyingFixture(t *testing.T, bridged bool) (Applier, networkplan.StagedPlan, string, *fakeApplyMachine, *fakeDHCP4Service, *fakeAccessPoint) {
	t.Helper()
	now := time.Unix(7000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	store := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	staged := wifiStagedPlan(t, now, bridged)
	spec, err := (Snapshotter{Store: store, HostRoot: hostRoot}).Capture(staged)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.HostapdManaged || spec.HostapdConfigExisted {
		t.Fatalf("Wi-Fi snapshot did not record the access point: %+v", spec)
	}
	validator := Validator{Store: store, Runner: &recordingRunner{}, Now: func() time.Time { return now.Add(time.Second) }}
	if _, err := validator.Validate(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	manifest, err := networktransaction.NewWatchdogManifest(*staged.Transaction, now.Add(2*time.Second), 2*time.Minute, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	record, err := staged.Transaction.ArmWatchdog(manifest.CreatedAt, manifest.ConfirmBy.Sub(manifest.CreatedAt))
	if err != nil {
		t.Fatal(err)
	}
	record, err = record.BeginApply(now.Add(3 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	staged.Transaction = &record
	staged.Status = string(record.Phase)
	machine := &fakeApplyMachine{}
	dhcp4 := &fakeDHCP4Service{}
	accessPoint := &fakeAccessPoint{machine: machine, dhcp4: dhcp4}
	return Applier{Store: store, HostRoot: hostRoot, Machine: machine, DHCP4: dhcp4, AccessPoint: accessPoint, IPv6: &fakeIPv6Machine{}}, staged, hostRoot, machine, dhcp4, accessPoint
}

func TestApplierWritesAccessPointConfigAndStartsItBeforeDHCP(t *testing.T) {
	for _, bridged := range []bool{false, true} {
		applier, staged, hostRoot, machine, dhcp4, accessPoint := wifiApplyingFixture(t, bridged)
		if err := applier.Apply(context.Background(), staged); err != nil {
			t.Fatal(err)
		}
		want := AccessPointTarget{Interface: "wlan0"}
		if bridged {
			want.Bridge = networkplan.LabBridgeName
		}
		if len(accessPoint.starts) != 1 || accessPoint.starts[0] != want {
			t.Fatalf("access point target is wrong: %+v", accessPoint.starts)
		}
		if accessPoint.machineCalls != 5 || accessPoint.dhcp4Calls != 0 || strings.Join(dhcp4.calls, ",") != "start" || len(machine.calls) != 5 {
			t.Fatalf("access point must start after Netplan and firewall and before DHCP: machine=%d dhcp=%d %v", accessPoint.machineCalls, accessPoint.dhcp4Calls, dhcp4.calls)
		}
		target := rootedPath(hostRoot, networkplan.ManagedHostapdPath)
		contents, err := os.ReadFile(target)
		expected, _ := networkplan.RenderHostapdConf(staged.Plan)
		if err != nil || string(contents) != expected || !strings.Contains(string(contents), "\nwpa_passphrase="+testAccessPointPassphrase+"\n") {
			t.Fatalf("hostapd configuration was not written with the password: %q %v", contents, err)
		}
		if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("hostapd configuration must be 0600: %v %v", info, err)
		}
		if info, err := os.Stat(filepath.Dir(target)); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("hostapd configuration directory must be 0700: %v %v", info, err)
		}
	}
}

func TestApplierRejectsTamperedAccessPointPreviewBeforeMutation(t *testing.T) {
	cases := map[string]func(*Applier, *networkplan.StagedPlan){
		"preview changed":    func(_ *Applier, staged *networkplan.StagedPlan) { staged.Preview.HostapdConf += "ap_isolate=0\n" },
		"preview missing":    func(_ *Applier, staged *networkplan.StagedPlan) { staged.Preview.HostapdConf = "" },
		"password changed":   func(_ *Applier, staged *networkplan.StagedPlan) { staged.Plan.WiFi.SSID = "Other" },
		"controller missing": func(applier *Applier, _ *networkplan.StagedPlan) { applier.AccessPoint = nil },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			applier, staged, hostRoot, machine, dhcp4, _ := wifiApplyingFixture(t, false)
			edit(&applier, &staged)
			if err := applier.Apply(context.Background(), staged); err == nil || !strings.Contains(err.Error(), "Wi-Fi") {
				t.Fatalf("tampered access point apply was not rejected: %v", err)
			}
			if len(machine.calls) != 0 || len(dhcp4.calls) != 0 {
				t.Fatalf("host mutated before access point rejection: %v %v", machine.calls, dhcp4.calls)
			}
			for _, path := range []string{managedNetplanPath, networkplan.ManagedHostapdPath} {
				if _, err := os.Lstat(rootedPath(hostRoot, path)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s was written before rejection: %v", path, err)
				}
			}
		})
	}
}

func TestApplierReturnsAccessPointStartFailureWithoutStartingDHCP(t *testing.T) {
	applier, staged, _, _, dhcp4, accessPoint := wifiApplyingFixture(t, true)
	accessPoint.startErr = errors.New("hostapd failed")
	err := applier.Apply(context.Background(), staged)
	if err == nil || !strings.Contains(err.Error(), "Wi-Fi access point") {
		t.Fatalf("access point failure was not returned: %v", err)
	}
	if len(dhcp4.calls) != 0 {
		t.Fatalf("DHCPv4 started after access point failure: %v", dhcp4.calls)
	}
}

func TestApplierLeavesAccessPointAloneForWiredPlans(t *testing.T) {
	applier, staged, hostRoot, _, _, _ := applyingFixtureWithAccessPoint(t)
	if err := applier.Apply(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if fake := applier.AccessPoint.(*fakeAccessPoint); len(fake.starts) != 0 || fake.disables != 0 {
		t.Fatalf("wired plan touched the access point: %+v", fake)
	}
	if _, err := os.Lstat(rootedPath(hostRoot, networkplan.ManagedHostapdPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wired plan wrote a hostapd configuration: %v", err)
	}
}

func applyingFixtureWithAccessPoint(t *testing.T) (Applier, networkplan.StagedPlan, string, *fakeApplyMachine, *fakeDHCP4Service, *fakeAccessPoint) {
	applier, staged, hostRoot, machine, dhcp4 := applyingFixture(t)
	accessPoint := &fakeAccessPoint{}
	applier.AccessPoint = accessPoint
	return applier, staged, hostRoot, machine, dhcp4, accessPoint
}

func TestSnapshotterBacksUpExistingAccessPointConfig(t *testing.T) {
	now := time.Unix(4000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	target := rootedPath(hostRoot, networkplan.ManagedHostapdPath)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("interface=wlan9\n")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	store := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	spec, err := (Snapshotter{Store: store, HostRoot: hostRoot}).Capture(wifiStagedPlan(t, now, false))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(original)
	if !spec.HostapdManaged || !spec.HostapdConfigExisted || spec.HostapdConfigSHA256 != hex.EncodeToString(sum[:]) || spec.HostapdConfigMode != 0o600 {
		t.Fatalf("existing hostapd configuration was not captured: %+v", spec)
	}
	directory, _ := store.TransactionDirectory(applyID)
	if backup, err := os.ReadFile(filepath.Join(directory, hostapdBackupName)); err != nil || string(backup) != string(original) {
		t.Fatalf("hostapd backup is wrong: %q %v", backup, err)
	}
	wired, err := (Snapshotter{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, HostRoot: hostRoot}).Capture(validStagedPlan(t, now))
	if err != nil || wired.HostapdManaged || wired.HostapdConfigExisted {
		t.Fatalf("wired plan recorded access point state: %+v %v", wired, err)
	}
}

func wifiRollbackFixture(t *testing.T, original []byte) (RollbackExecutor, networktransaction.WatchdogManifest, string, *fakeDHCP4Service, *fakeAccessPoint) {
	t.Helper()
	now := time.Unix(5000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	target := rootedPath(hostRoot, networkplan.ManagedHostapdPath)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if original != nil {
		if err := os.WriteFile(target, original, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	store := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	staged := wifiStagedPlan(t, now, true)
	spec, err := (Snapshotter{Store: store, HostRoot: hostRoot}).Capture(staged)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := networktransaction.NewWatchdogManifest(*staged.Transaction, now.Add(time.Second), 2*time.Minute, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("interface=wlan0\nwpa_passphrase=applied\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dhcp4 := &fakeDHCP4Service{}
	accessPoint := &fakeAccessPoint{dhcp4: dhcp4}
	return RollbackExecutor{Store: store, HostRoot: hostRoot, Machine: &fakeRollbackMachine{}, DHCP4: dhcp4, AccessPoint: accessPoint}, manifest, hostRoot, dhcp4, accessPoint
}

func TestRollbackStopsAccessPointAndRemovesNewConfig(t *testing.T) {
	executor, manifest, hostRoot, dhcp4, accessPoint := wifiRollbackFixture(t, nil)
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if accessPoint.disables != 1 || accessPoint.dhcp4Calls != 0 || strings.Join(dhcp4.calls, ",") != "disable" {
		t.Fatalf("access point must stop before DHCP during rollback: disables=%d dhcpBefore=%d dhcp=%v", accessPoint.disables, accessPoint.dhcp4Calls, dhcp4.calls)
	}
	if _, err := os.Lstat(rootedPath(hostRoot, networkplan.ManagedHostapdPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("applied hostapd configuration remained after rollback: %v", err)
	}
}

func TestRollbackRestoresPriorAccessPointConfig(t *testing.T) {
	original := []byte("interface=wlan9\n")
	executor, manifest, hostRoot, _, _ := wifiRollbackFixture(t, original)
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	target := rootedPath(hostRoot, networkplan.ManagedHostapdPath)
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != string(original) {
		t.Fatalf("prior hostapd configuration was not restored: %q %v", contents, err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("prior hostapd mode was not restored: %v %v", info, err)
	}
}

func TestRollbackAttemptsEveryAccessPointStep(t *testing.T) {
	executor, manifest, hostRoot, dhcp4, accessPoint := wifiRollbackFixture(t, []byte("interface=wlan9\n"))
	directory, _ := executor.Store.TransactionDirectory(manifest.ApplyID)
	if err := os.WriteFile(filepath.Join(directory, hostapdBackupName), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	accessPoint.disableErr = errors.New("systemd unavailable")
	err := executor.Execute(context.Background(), manifest)
	if err == nil || !strings.Contains(err.Error(), "digest") || !strings.Contains(err.Error(), "stop ShakerProxy Wi-Fi access point") {
		t.Fatalf("access point rollback failures were hidden: %v", err)
	}
	if accessPoint.disables != 1 || strings.Join(dhcp4.calls, ",") != "disable" {
		t.Fatalf("rollback stopped early: disables=%d dhcp=%v", accessPoint.disables, dhcp4.calls)
	}
	if contents, _ := os.ReadFile(rootedPath(hostRoot, networkplan.ManagedHostapdPath)); strings.Contains(string(contents), "tampered") {
		t.Fatal("an unverified backup was restored")
	}

	executor, manifest, _, _, _ = wifiRollbackFixture(t, nil)
	executor.AccessPoint = nil
	if err := executor.Execute(context.Background(), manifest); err == nil || !strings.Contains(err.Error(), "rollback controller") {
		t.Fatalf("missing access point controller was ignored: %v", err)
	}
}

func TestWiredRollbackNeverTouchesAccessPoint(t *testing.T) {
	executor, manifest, _, _, _ := rollbackFixture(t, nil, "0\n")
	accessPoint := &fakeAccessPoint{}
	executor.AccessPoint = accessPoint
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if accessPoint.disables != 0 {
		t.Fatal("wired rollback stopped the access point unit")
	}
	executor.AccessPoint = nil
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatalf("wired rollback required an access point controller: %v", err)
	}
}

type recordedCommand struct {
	path string
	args string
}

func osAccessPointFixture(files map[string]string, exitCodes map[string]int) (*[]recordedCommand, OSAccessPointService) {
	calls := &[]recordedCommand{}
	service := OSAccessPointService{
		run: func(_ context.Context, path string, arguments []string) (rollbackCommandResult, error) {
			joined := strings.Join(arguments, " ")
			*calls = append(*calls, recordedCommand{path: path, args: joined})
			return rollbackCommandResult{exitCode: exitCodes[joined]}, nil
		},
		readFile: func(path string) ([]byte, error) {
			if value, ok := files[path]; ok {
				return []byte(value), nil
			}
			return nil, os.ErrNotExist
		},
		readyTimeout: 50 * time.Millisecond,
		pollInterval: time.Millisecond,
	}
	return calls, service
}

func TestOSAccessPointServiceRestartsAndWaitsForBridgedAccessPoint(t *testing.T) {
	calls, service := osAccessPointFixture(map[string]string{
		"/sys/class/net/wlan0/operstate":        "up\n",
		"/sys/class/net/lgbr0/brif/wlan0/state": "3\n",
	}, nil)
	if err := service.StartAccessPoint(context.Background(), AccessPointTarget{Interface: "wlan0", Bridge: networkplan.LabBridgeName}); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || (*calls)[0] != (recordedCommand{path: "/usr/bin/systemctl", args: "restart shakerproxy-hostapd.service"}) {
		t.Fatalf("unexpected access point commands: %+v", *calls)
	}
	if err := service.EnsureAccessPointEnabled(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.DisableAccessPoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (*calls)[1].args != "enable shakerproxy-hostapd.service" || (*calls)[2].args != "disable --now shakerproxy-hostapd.service" {
		t.Fatalf("unexpected enable/disable commands: %+v", *calls)
	}
}

func TestOSAccessPointServiceExplainsStartFailures(t *testing.T) {
	_, service := osAccessPointFixture(map[string]string{"/sys/class/net/wlan0/operstate": "up\n"}, map[string]int{"is-active --quiet shakerproxy-hostapd.service": 3})
	err := service.StartAccessPoint(context.Background(), AccessPointTarget{Interface: "wlan0", Bridge: networkplan.LabBridgeName})
	if err == nil || !strings.Contains(err.Error(), "hostapd stopped") || !strings.Contains(err.Error(), "journalctl -u shakerproxy-hostapd.service") {
		t.Fatalf("stopped hostapd was not explained: %v", err)
	}
	_, service = osAccessPointFixture(map[string]string{"/sys/class/net/wlan0/operstate": "dormant\n"}, nil)
	err = service.StartAccessPoint(context.Background(), AccessPointTarget{Interface: "wlan0"})
	if err == nil || !strings.Contains(err.Error(), "did not come up") {
		t.Fatalf("slow access point was not explained: %v", err)
	}
	calls, service := osAccessPointFixture(nil, map[string]int{"restart shakerproxy-hostapd.service": 1})
	if err := service.StartAccessPoint(context.Background(), AccessPointTarget{Interface: "wlan0"}); err == nil || len(*calls) != 1 {
		t.Fatalf("restart failure was not returned immediately: %v %+v", err, *calls)
	}
	for _, target := range []AccessPointTarget{{Interface: "wlan0;reboot"}, {Interface: "wlan0:1"}, {Interface: ""}, {Interface: "wlan0", Bridge: "br0"}} {
		calls, service := osAccessPointFixture(nil, nil)
		if err := service.StartAccessPoint(context.Background(), target); err == nil || len(*calls) != 0 {
			t.Fatalf("unsafe target %+v reached systemctl: %v %+v", target, err, *calls)
		}
	}
}

func TestAccessPointCommandAllowlistIsExact(t *testing.T) {
	for _, arguments := range [][]string{
		{"restart", "shakerproxy-hostapd.service"},
		{"enable", "shakerproxy-hostapd.service"},
		{"disable", "--now", "shakerproxy-hostapd.service"},
		{"is-active", "--quiet", "shakerproxy-hostapd.service"},
	} {
		if !allowedAccessPointCommand("/usr/bin/systemctl", arguments) {
			t.Fatalf("exact access point command rejected: %q", arguments)
		}
	}
	for _, rejected := range []struct {
		path string
		args []string
	}{
		{"/usr/bin/systemctl", []string{"restart", "hostapd.service"}},
		{"/usr/bin/systemctl", []string{"start", "shakerproxy-hostapd.service"}},
		{"/usr/bin/systemctl", []string{"restart", "shakerproxy-hostapd.service", "shakerproxy-gatewayd.service"}},
		{"/usr/bin/systemctl", []string{"disable", "shakerproxy-hostapd.service"}},
		{"/usr/bin/systemctl", []string{"mask", "shakerproxy-hostapd.service"}},
		{"/usr/bin/systemctl", []string{"restart", "shakerproxy-hostapd@wlan0.service"}},
		{"/bin/systemctl", []string{"restart", "shakerproxy-hostapd.service"}},
		{"/usr/sbin/hostapd", []string{"-B", "/etc/shakerproxy/hostapd/shakerproxy.conf"}},
		{"/bin/sh", []string{"-c", "systemctl restart shakerproxy-hostapd.service"}},
	} {
		if allowedAccessPointCommand(rejected.path, rejected.args) {
			t.Fatalf("broad access point command allowlisted: %s %q", rejected.path, rejected.args)
		}
	}
	if allowedApplyCommand("/usr/bin/systemctl", []string{"restart", "shakerproxy-hostapd.service"}, "") || allowedRollbackCommand("/usr/bin/systemctl", []string{"disable", "--now", "shakerproxy-hostapd.service"}) {
		t.Fatal("access point commands leaked into the network apply or rollback allowlists")
	}
	if _, err := runAccessPointCommand(context.Background(), "/usr/bin/systemctl", []string{"stop", "shakerproxy-gatewayd.service"}); err == nil {
		t.Fatal("unlisted command reached exec")
	}
}
