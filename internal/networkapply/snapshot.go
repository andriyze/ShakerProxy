package networkapply

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const (
	managedNetplanPath = "/etc/netplan/90-shakerproxy.yaml"
	managedDHCP4Path   = "/etc/kea/kea-dhcp4.conf"
)

type Snapshotter struct {
	Store    networktransaction.FileStore
	HostRoot string
}

func (s Snapshotter) Capture(staged networkplan.StagedPlan) (networktransaction.RollbackSpec, error) {
	if staged.Transaction == nil || staged.Transaction.Phase != networktransaction.PhasePreparing {
		return networktransaction.RollbackSpec{}, errors.New("rollback snapshot requires a preparing network transaction")
	}
	if err := staged.Transaction.Validate(); err != nil {
		return networktransaction.RollbackSpec{}, err
	}
	if staged.ApplyID != staged.Transaction.ApplyID || staged.PlanHash != staged.Transaction.PlanHash {
		return networktransaction.RollbackSpec{}, errors.New("staged plan and transaction identity do not match")
	}
	if !staged.Preview.Validation.Valid || staged.Preview.Validation.PlanHash != staged.PlanHash {
		return networktransaction.RollbackSpec{}, errors.New("staged preview validation does not match the transaction")
	}
	inspection := staged.Preview.FirewallEnvironment
	if !inspection.ApplyReady || inspection.ShakerProxyFilterChain || inspection.ShakerProxyNATChain {
		return networktransaction.RollbackSpec{}, errors.New("firewall environment is not safe for initial rollback capture")
	}
	spec := networktransaction.RollbackSpec{InitialMode: "SETUP_SAFE_NO_SHAKERPROXY", IptablesPath: inspection.IptablesPath}
	if !filepath.IsAbs(s.HostRoot) {
		return networktransaction.RollbackSpec{}, errors.New("host root must be absolute")
	}
	directory, err := s.Store.TransactionDirectory(staged.ApplyID)
	if err != nil {
		return networktransaction.RollbackSpec{}, err
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return networktransaction.RollbackSpec{}, err
	}
	netplan, err := captureManagedFile(s.HostRoot, managedNetplanPath, directory, "netplan.before", "Netplan")
	if err != nil {
		return networktransaction.RollbackSpec{}, err
	}
	spec.NetplanExisted, spec.NetplanSHA256, spec.NetplanMode = netplan.existed, netplan.sha256, netplan.mode
	dhcp4, err := captureManagedFile(s.HostRoot, managedDHCP4Path, directory, "dhcp4.before", "DHCPv4 configuration")
	if err != nil {
		return networktransaction.RollbackSpec{}, err
	}
	spec.DHCP4ConfigExisted, spec.DHCP4ConfigSHA256, spec.DHCP4ConfigMode = dhcp4.existed, dhcp4.sha256, dhcp4.mode
	if err := captureAccessPoint(s.HostRoot, staged, directory, &spec); err != nil {
		return networktransaction.RollbackSpec{}, err
	}
	forwardingRaw, err := os.ReadFile(rootedPath(s.HostRoot, "/proc/sys/net/ipv4/ip_forward"))
	if err != nil {
		return networktransaction.RollbackSpec{}, fmt.Errorf("read IPv4 forwarding state: %w", err)
	}
	switch strings.TrimSpace(string(forwardingRaw)) {
	case "0":
		spec.IPv4Forwarding = 0
	case "1":
		spec.IPv4Forwarding = 1
	default:
		return networktransaction.RollbackSpec{}, errors.New("IPv4 forwarding state is not zero or one")
	}
	if staged.Plan.Topology == networkplan.TopologySingleArm {
		arm, ok := networkplan.WANInterface(staged.Plan)
		if !ok {
			return networktransaction.RollbackSpec{}, errors.New("single-arm interface is unavailable for rollback capture")
		}
		redirectsRaw, readErr := os.ReadFile(rootedPath(s.HostRoot, "/proc/sys/net/ipv4/conf/"+arm.CurrentName+"/send_redirects"))
		if readErr != nil {
			return networktransaction.RollbackSpec{}, fmt.Errorf("read IPv4 redirect state: %w", readErr)
		}
		spec.IPv4SendRedirectsInterface = arm.CurrentName
		switch strings.TrimSpace(string(redirectsRaw)) {
		case "0":
			spec.IPv4SendRedirects = 0
		case "1":
			spec.IPv4SendRedirects = 1
		default:
			return networktransaction.RollbackSpec{}, errors.New("IPv4 redirect state is not zero or one")
		}
	}
	if networkplan.InlineBridge(staged.Plan) {
		bridgeRaw, readErr := os.ReadFile(rootedPath(s.HostRoot, bridgeNFCallIPTablesPath))
		if errors.Is(readErr, os.ErrNotExist) {
			return networktransaction.RollbackSpec{}, errors.New("an inline bridge needs the br_netfilter kernel module, which Docker normally loads; run sudo modprobe br_netfilter and try again")
		}
		if readErr != nil {
			return networktransaction.RollbackSpec{}, fmt.Errorf("read bridge netfilter state: %w", readErr)
		}
		spec.BridgeNetfilter = true
		switch strings.TrimSpace(string(bridgeRaw)) {
		case "0":
			spec.BridgeNFCallIPTables = 0
		case "1":
			spec.BridgeNFCallIPTables = 1
		default:
			return networktransaction.RollbackSpec{}, errors.New("bridge netfilter state is not zero or one")
		}
	}
	if spec.IPv6, err = captureIPv6State(s.HostRoot, staged, directory); err != nil {
		return networktransaction.RollbackSpec{}, err
	}
	if err := spec.Validate(); err != nil {
		return networktransaction.RollbackSpec{}, err
	}
	if err := writeAtomicJSON(directory, "rollback-spec.json", spec); err != nil {
		return networktransaction.RollbackSpec{}, fmt.Errorf("persist rollback specification: %w", err)
	}
	return spec, nil
}

type managedFileSnapshot struct {
	existed bool
	sha256  string
	mode    uint32
}

func captureManagedFile(hostRoot, managedPath, directory, backupName, label string) (managedFileSnapshot, error) {
	target := rootedPath(hostRoot, managedPath)
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return managedFileSnapshot{}, nil
	}
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return managedFileSnapshot{}, fmt.Errorf("inspect managed %s file: %w (the gateway service cannot open %s; run sudo shakerproxy doctor)", label, err, filepath.Dir(target))
		}
		return managedFileSnapshot{}, fmt.Errorf("inspect managed %s file: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return managedFileSnapshot{}, fmt.Errorf("managed %s path is not a regular file", label)
	}
	if info.Size() > maxArtifactBytes {
		return managedFileSnapshot{}, fmt.Errorf("existing managed %s file exceeds backup limit", label)
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		return managedFileSnapshot{}, fmt.Errorf("read existing managed %s file: %w", label, err)
	}
	if err := writeAtomicFile(directory, backupName, contents, 0o600); err != nil {
		return managedFileSnapshot{}, fmt.Errorf("persist %s backup: %w", label, err)
	}
	sum := sha256.Sum256(contents)
	return managedFileSnapshot{existed: true, sha256: hex.EncodeToString(sum[:]), mode: uint32(info.Mode().Perm())}, nil
}

func rootedPath(root, absolute string) string {
	return filepath.Join(filepath.Clean(root), strings.TrimPrefix(absolute, "/"))
}
