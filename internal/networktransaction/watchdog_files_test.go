package networktransaction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func preparingRecord(t *testing.T, now time.Time) Record {
	t.Helper()
	record, err := New(testApplyID, testPlanHash, now)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func rollbackSpec() RollbackSpec {
	return RollbackSpec{InitialMode: "SETUP_SAFE_NO_SHAKERPROXY", IPv4Forwarding: 0, IptablesPath: "/usr/sbin/iptables"}
}

func TestRollbackSpecValidatesSingleArmRedirectIdentity(t *testing.T) {
	spec := rollbackSpec()
	spec.IPv4SendRedirectsInterface = "eth0"
	spec.IPv4SendRedirects = 1
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	spec.IPv4SendRedirectsInterface = "eth0;reboot"
	if err := spec.Validate(); err == nil {
		t.Fatal("injected single-arm interface was accepted")
	}
}

func TestFileStoreWritesStrictHashBoundManifestAndConfirmation(t *testing.T) {
	now := time.Unix(2000, 0)
	manifest, err := NewWatchdogManifest(preparingRecord(t, now), now, 2*time.Minute, rollbackSpec())
	if err != nil {
		t.Fatal(err)
	}
	store := FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatalf("identical manifest retry was not idempotent: %v", err)
	}
	changed := manifest
	changed.ConfirmBy = changed.ConfirmBy.Add(time.Second)
	if err := store.WriteManifest(changed); err == nil {
		t.Fatal("existing watchdog deadline was overwritten")
	}
	loaded, err := store.ReadManifest(testApplyID)
	if err != nil || loaded != manifest {
		t.Fatalf("manifest round trip failed: loaded=%+v err=%v", loaded, err)
	}
	if _, err := store.Confirm(testApplyID, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", now.Add(time.Second)); err == nil {
		t.Fatal("mismatched plan hash was confirmed")
	}
	if _, err := store.Confirm(testApplyID, testPlanHash, manifest.ConfirmBy); err == nil {
		t.Fatal("deadline-inclusive confirmation was accepted")
	}
	firstConfirmation, err := store.Confirm(testApplyID, testPlanHash, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	secondConfirmation, err := store.Confirm(testApplyID, testPlanHash, now.Add(2*time.Second))
	if err != nil || secondConfirmation != firstConfirmation {
		t.Fatalf("confirmation retry changed its durable marker: first=%+v second=%+v err=%v", firstConfirmation, secondConfirmation, err)
	}
	confirmed, err := store.IsConfirmed(manifest)
	if err != nil || !confirmed {
		t.Fatalf("valid marker was not accepted: confirmed=%v err=%v", confirmed, err)
	}
	info, err := os.Stat(filepath.Join(store.Root, testApplyID, "confirmed.json"))
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("unexpected confirmation permissions: info=%v err=%v", info, err)
	}
}

func TestFileStoreRejectsTraversalUnknownFieldsAndOversize(t *testing.T) {
	store := FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	if _, err := store.ReadManifest("../../etc"); err == nil {
		t.Fatal("traversal apply ID accepted")
	}
	directory := filepath.Join(store.Root, testApplyID)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), []byte(`{"schema":1,"unknown":true}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadManifest(testApplyID); err == nil {
		t.Fatal("unknown manifest field accepted")
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), make([]byte, maxWatchdogFileBytes+1), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadManifest(testApplyID); err == nil {
		t.Fatal("oversize manifest accepted")
	}
}

type recordingCommandRunner struct {
	path string
	args []string
	err  error
}

type sequenceCommandRunner struct {
	calls []struct {
		path string
		args []string
	}
	errors []error
}

func (r *sequenceCommandRunner) Run(_ context.Context, path string, args ...string) error {
	r.calls = append(r.calls, struct {
		path string
		args []string
	}{path: path, args: append([]string(nil), args...)})
	if len(r.errors) == 0 {
		return nil
	}
	err := r.errors[0]
	r.errors = r.errors[1:]
	return err
}

func (r *recordingCommandRunner) Run(_ context.Context, path string, args ...string) error {
	r.path = path
	r.args = append([]string(nil), args...)
	return r.err
}

func TestSystemdWatchdogUsesFixedExecutableAndDerivedIdentity(t *testing.T) {
	now := time.Unix(2000, 0)
	manifest, err := NewWatchdogManifest(preparingRecord(t, now), now, 2*time.Minute, rollbackSpec())
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{}
	watchdog := SystemdWatchdog{Runner: runner}
	if err := watchdog.Arm(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"--unit=shakerproxy-network-watchdog-0123456789abcdef0123456789abcdef",
		"--collect", "--service-type=exec", "--property=NoNewPrivileges=yes",
		"--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
		"--property=CapabilityBoundingSet=CAP_NET_ADMIN",
		"--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6",
		"--property=LockPersonality=yes", "--property=MemoryDenyWriteExecute=yes", "--property=RestrictSUIDSGID=yes",
		"--property=ReadWritePaths=/run/lock/shakerproxy " + DefaultTransactionRoot + " /etc/netplan /etc/kea /etc/systemd/system /run/systemd/system /run/systemd/network /run/udev/rules.d -/etc/shakerproxy/hostapd -/etc/shakerproxy/radvd",
		watchdogExecutable, "--apply-id", testApplyID,
	}
	if runner.path != "/usr/bin/systemd-run" || !reflect.DeepEqual(runner.args, expected) {
		t.Fatalf("unexpected watchdog command: %s %q", runner.path, runner.args)
	}
	if !allowedWatchdogCommand(runner.path, runner.args) {
		t.Fatal("generated watchdog command was not allowlisted")
	}
	if err := watchdog.Disarm(context.Background(), testApplyID); err != nil {
		t.Fatal(err)
	}
	if runner.path != "/usr/bin/systemctl" || !reflect.DeepEqual(runner.args, []string{"stop", watchdogUnit(testApplyID) + ".service"}) {
		t.Fatalf("unexpected disarm command: %s %q", runner.path, runner.args)
	}
}

func TestSystemdWatchdogRejectsInjectedIdentityAndPropagatesFailure(t *testing.T) {
	runner := &recordingCommandRunner{err: errors.New("systemd unavailable")}
	watchdog := SystemdWatchdog{Runner: runner}
	if err := watchdog.Disarm(context.Background(), "apply-good;shutdown"); err == nil {
		t.Fatal("injected apply ID accepted")
	}
	now := time.Unix(2000, 0)
	manifest, _ := NewWatchdogManifest(preparingRecord(t, now), now, 2*time.Minute, rollbackSpec())
	if err := watchdog.Arm(context.Background(), manifest); err == nil {
		t.Fatal("systemd launch failure was ignored")
	}
	if allowedWatchdogCommand("/bin/sh", []string{"-c", "systemctl stop '*'"}) {
		t.Fatal("shell command was allowlisted")
	}
	if allowedWatchdogCommand("/usr/bin/systemctl", []string{"stop", "shakerproxy-network-watchdog-;shutdown.service"}) {
		t.Fatal("injected unit name was allowlisted")
	}
}

func TestSystemdWatchdogEnsureArmedPreservesActiveUnit(t *testing.T) {
	now := time.Unix(2000, 0)
	manifest, err := NewWatchdogManifest(preparingRecord(t, now), now, 2*time.Minute, rollbackSpec())
	if err != nil {
		t.Fatal(err)
	}
	runner := &sequenceCommandRunner{}
	watchdog := SystemdWatchdog{Runner: runner}
	if err := watchdog.EnsureArmed(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	expected := []string{"is-active", "--quiet", watchdogUnit(testApplyID) + ".service"}
	if len(runner.calls) != 1 || runner.calls[0].path != "/usr/bin/systemctl" || !reflect.DeepEqual(runner.calls[0].args, expected) {
		t.Fatalf("active watchdog was not preserved: %+v", runner.calls)
	}
}

func TestSystemdWatchdogEnsureArmedRecreatesMissingUnit(t *testing.T) {
	now := time.Unix(2000, 0)
	manifest, err := NewWatchdogManifest(preparingRecord(t, now), now, 2*time.Minute, rollbackSpec())
	if err != nil {
		t.Fatal(err)
	}
	runner := &sequenceCommandRunner{errors: []error{errors.New("unit inactive")}}
	watchdog := SystemdWatchdog{Runner: runner}
	if err := watchdog.EnsureArmed(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[0].path != "/usr/bin/systemctl" || runner.calls[1].path != "/usr/bin/systemd-run" {
		t.Fatalf("missing watchdog was not recreated: %+v", runner.calls)
	}
	if !allowedWatchdogCommand(runner.calls[0].path, runner.calls[0].args) || !allowedWatchdogCommand(runner.calls[1].path, runner.calls[1].args) {
		t.Fatal("recovery watchdog command was not allowlisted")
	}
}
