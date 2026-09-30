package networkapply

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

func prepareHostRoot(t *testing.T, forwarding string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "netplan"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "proc", "sys", "net", "ipv4"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc", "sys", "net", "ipv4", "ip_forward"), []byte(forwarding), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func prepareRedirectState(t *testing.T, root, interfaceName, value string) {
	t.Helper()
	directory := filepath.Join(root, "proc", "sys", "net", "ipv4", "conf", interfaceName)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "send_redirects"), []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotterCapturesExactNetplanAndForwardingState(t *testing.T) {
	now := time.Unix(4000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	original := []byte("network:\n  version: 2\n")
	target := rootedPath(hostRoot, managedNetplanPath)
	if err := os.WriteFile(target, original, 0o640); err != nil {
		t.Fatal(err)
	}
	dhcp4Original := []byte("{\"Dhcp4\":{}}\n")
	dhcp4Target := rootedPath(hostRoot, managedDHCP4Path)
	if err := os.MkdirAll(filepath.Dir(dhcp4Target), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dhcp4Target, dhcp4Original, 0o640); err != nil {
		t.Fatal(err)
	}
	transactionRoot := filepath.Join(t.TempDir(), "transactions")
	snapshotter := Snapshotter{Store: networktransaction.FileStore{Root: transactionRoot}, HostRoot: hostRoot}
	spec, err := snapshotter.Capture(validStagedPlan(t, now))
	if err != nil {
		t.Fatal(err)
	}
	if !spec.NetplanExisted || spec.NetplanMode != 0o640 || len(spec.NetplanSHA256) != 64 || !spec.DHCP4ConfigExisted || spec.DHCP4ConfigMode != 0o640 || len(spec.DHCP4ConfigSHA256) != 64 || spec.IPv4Forwarding != 0 || spec.IptablesPath != "/usr/sbin/iptables" {
		t.Fatalf("unexpected rollback snapshot: %+v", spec)
	}
	backup := filepath.Join(transactionRoot, applyID, "netplan.before")
	contents, err := os.ReadFile(backup)
	if err != nil || string(contents) != string(original) {
		t.Fatalf("backup mismatch: contents=%q err=%v", contents, err)
	}
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected backup mode: info=%v err=%v", info, err)
	}
	dhcp4Backup := filepath.Join(transactionRoot, applyID, "dhcp4.before")
	contents, err = os.ReadFile(dhcp4Backup)
	if err != nil || string(contents) != string(dhcp4Original) {
		t.Fatalf("DHCPv4 backup mismatch: contents=%q err=%v", contents, err)
	}
}

func TestSnapshotterRecordsAbsentNetplan(t *testing.T) {
	now := time.Unix(4000, 0)
	hostRoot := prepareHostRoot(t, "1\n")
	snapshotter := Snapshotter{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, HostRoot: hostRoot}
	spec, err := snapshotter.Capture(validStagedPlan(t, now))
	if err != nil {
		t.Fatal(err)
	}
	if spec.NetplanExisted || spec.NetplanSHA256 != "" || spec.NetplanMode != 0 || spec.DHCP4ConfigExisted || spec.DHCP4ConfigSHA256 != "" || spec.DHCP4ConfigMode != 0 || spec.IPv4Forwarding != 1 {
		t.Fatalf("unexpected absent-file snapshot: %+v", spec)
	}
}

func TestSnapshotterCapturesSingleArmRedirectState(t *testing.T) {
	now := time.Unix(4000, 0)
	hostRoot := prepareHostRoot(t, "1\n")
	prepareRedirectState(t, hostRoot, "eth0", "1\n")
	snapshotter := Snapshotter{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, HostRoot: hostRoot}
	spec, err := snapshotter.Capture(singleArmStagedPlan(t, now))
	if err != nil {
		t.Fatal(err)
	}
	if spec.IPv4SendRedirectsInterface != "eth0" || spec.IPv4SendRedirects != 1 {
		t.Fatalf("single-arm redirect state was not captured: %+v", spec)
	}
}

func TestSnapshotterRejectsSymlinkInvalidForwardingAndFirewallConflict(t *testing.T) {
	now := time.Unix(4000, 0)
	t.Run("symlink", func(t *testing.T) {
		hostRoot := prepareHostRoot(t, "0\n")
		if err := os.Symlink("/etc/passwd", rootedPath(hostRoot, managedNetplanPath)); err != nil {
			t.Fatal(err)
		}
		snapshotter := Snapshotter{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, HostRoot: hostRoot}
		if _, err := snapshotter.Capture(validStagedPlan(t, now)); err == nil {
			t.Fatal("Netplan symlink was accepted")
		}
	})
	t.Run("forwarding", func(t *testing.T) {
		hostRoot := prepareHostRoot(t, "enabled\n")
		snapshotter := Snapshotter{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, HostRoot: hostRoot}
		if _, err := snapshotter.Capture(validStagedPlan(t, now)); err == nil {
			t.Fatal("invalid forwarding state was accepted")
		}
	})
	t.Run("DHCPv4 symlink", func(t *testing.T) {
		hostRoot := prepareHostRoot(t, "0\n")
		target := rootedPath(hostRoot, managedDHCP4Path)
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/passwd", target); err != nil {
			t.Fatal(err)
		}
		snapshotter := Snapshotter{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, HostRoot: hostRoot}
		if _, err := snapshotter.Capture(validStagedPlan(t, now)); err == nil {
			t.Fatal("DHCPv4 configuration symlink was accepted")
		}
	})
	t.Run("firewall conflict", func(t *testing.T) {
		hostRoot := prepareHostRoot(t, "0\n")
		staged := validStagedPlan(t, now)
		staged.Preview.FirewallEnvironment.ShakerProxyFilterChain = true
		snapshotter := Snapshotter{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, HostRoot: hostRoot}
		if _, err := snapshotter.Capture(staged); err == nil {
			t.Fatal("reserved firewall chain conflict was accepted")
		}
	})
}
