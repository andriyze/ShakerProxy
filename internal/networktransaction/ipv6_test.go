package networktransaction

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validRoutedIPv6Spec() IPv6RollbackSpec {
	return IPv6RollbackSpec{
		Firewall: IPv6FirewallRoute, Ip6tablesPath: "/usr/sbin/ip6tables", ForwardParent: "DOCKER-USER", NAT66: true,
		Forwarding: 0, AcceptRAInterface: "enp1s0", AcceptRA: 1,
		RadvdConfigExisted: true, RadvdConfigSHA256: strings.Repeat("a", 64), RadvdConfigMode: 0o644,
	}
}

func TestIPv6RollbackSpecValidation(t *testing.T) {
	if err := (IPv6RollbackSpec{}).Validate(); err != nil {
		t.Fatalf("zero IPv6 rollback state must stay valid for older manifests: %v", err)
	}
	if err := validRoutedIPv6Spec().Validate(); err != nil {
		t.Fatal(err)
	}
	block := IPv6RollbackSpec{Firewall: IPv6FirewallBlock, Ip6tablesPath: "/usr/bin/ip6tables", ForwardParent: "FORWARD"}
	if err := block.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := []func(*IPv6RollbackSpec){
		func(spec *IPv6RollbackSpec) { spec.Firewall = "ALLOW" },
		func(spec *IPv6RollbackSpec) { spec.Ip6tablesPath = "/tmp/ip6tables" },
		func(spec *IPv6RollbackSpec) { spec.ForwardParent = "INPUT" },
		func(spec *IPv6RollbackSpec) { spec.Forwarding = 2 },
		func(spec *IPv6RollbackSpec) { spec.AcceptRAInterface = "eth0;reboot" },
		func(spec *IPv6RollbackSpec) { spec.AcceptRA = 2 },
		func(spec *IPv6RollbackSpec) { spec.AcceptRAInterface, spec.AcceptRA = "", 1 },
		func(spec *IPv6RollbackSpec) { spec.RadvdConfigSHA256 = "short" },
		func(spec *IPv6RollbackSpec) { spec.RadvdConfigExisted = false },
		func(spec *IPv6RollbackSpec) { spec.RadvdConfigMode = 0o4755 },
	}
	for index, edit := range invalid {
		spec := validRoutedIPv6Spec()
		edit(&spec)
		if err := spec.Validate(); err == nil {
			t.Fatalf("invalid IPv6 rollback state %d was accepted: %+v", index, spec)
		}
	}
	blockWithRouting := block
	blockWithRouting.Forwarding = 1
	if err := blockWithRouting.Validate(); err == nil {
		t.Fatal("blocked lab IPv6 recorded routing state")
	}
	orphan := IPv6RollbackSpec{ForwardParent: "FORWARD"}
	if err := orphan.Validate(); err == nil {
		t.Fatal("IPv6 firewall state without a mode was accepted")
	}
}

func TestRollbackSpecBindsIp6tablesToTheApprovedIptablesPath(t *testing.T) {
	spec := RollbackSpec{InitialMode: "SETUP_SAFE_NO_SHAKERPROXY", IptablesPath: "/usr/sbin/iptables", IPv6: validRoutedIPv6Spec()}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	spec.IPv6.Ip6tablesPath = "/usr/bin/ip6tables"
	if err := spec.Validate(); err == nil {
		t.Fatal("mismatched ip6tables path was accepted")
	}
}

func TestManifestWithoutIPv6RemainsStrictlyDecodableAndComparable(t *testing.T) {
	manifest := WatchdogManifest{Schema: SchemaVersion, ApplyID: "apply-0123456789abcdef0123456789abcdef", PlanHash: strings.Repeat("b", 64), CreatedAt: time.Unix(10, 0).UTC(), ConfirmBy: time.Unix(130, 0).UTC(), Rollback: RollbackSpec{InitialMode: "SETUP_SAFE_NO_SHAKERPROXY", IptablesPath: "/usr/sbin/iptables"}}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"ipv6"`) {
		t.Fatalf("IPv6-free manifest changed its encoding: %s", encoded)
	}
	withIPv6 := manifest
	withIPv6.Rollback.IPv6 = validRoutedIPv6Spec()
	if withIPv6 == manifest {
		t.Fatal("IPv6 rollback state does not participate in manifest equality")
	}
	encoded, err = json.Marshal(withIPv6)
	if err != nil || !strings.Contains(string(encoded), `"ipv6":{"firewall":"ROUTE"`) {
		t.Fatalf("IPv6 rollback state was not encoded: %s err=%v", encoded, err)
	}
}
