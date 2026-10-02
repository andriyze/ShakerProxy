package daemon

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

func TestDiagnosticsAreBoundedOrderedAndReadOnly(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	report := server.inspectDiagnostics(context.Background())
	if report.Schema != diagnosticSchema || report.GeneratedAt.IsZero() || len(report.Checks) != 14 {
		t.Fatalf("unexpected diagnostic report: %#v", report)
	}
	expected := []string{"interfaces", "firewall", "routes", "dns", "service_ports", "forwarding", "dhcp", "docker", "services", "disk", "resource_pressure", "time_sync", "capture", "packet_drops"}
	for index, check := range report.Checks {
		if check.Name != expected[index] || len(check.Summary) < 1 || len(check.Summary) > 256 || len(check.Observations) > 8 {
			t.Fatalf("unbounded or unordered diagnostic check %d: %#v", index, check)
		}
		for _, observation := range check.Observations {
			if len(observation) > 256 {
				t.Fatalf("unbounded diagnostic observation: %q", observation)
			}
		}
		switch check.Status {
		case gatewayprotocol.DiagnosticPass, gatewayprotocol.DiagnosticWarning, gatewayprotocol.DiagnosticFail, gatewayprotocol.DiagnosticUnknown:
		default:
			t.Fatalf("unsupported diagnostic status: %q", check.Status)
		}
	}
	if active, known := diagnosticServiceActive(context.Background(), "attacker.service"); active || known {
		t.Fatal("diagnostics accepted a caller-selected service")
	}
}

func TestDiagnosticTextTruncationPreservesUTF8(t *testing.T) {
	value := boundedDiagnosticText("  "+string([]rune{'é', 'é', 'é'})+"\nsecret\x00detail  ", 7)
	if value != "ééé" {
		t.Fatalf("diagnostic truncation was unsafe: %q", value)
	}
}

func TestDefaultRouteInterfacesBindWANWithoutDNSOrCommands(t *testing.T) {
	ipv4 := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nens3 00000000 010200C0 0003 0 0 100 00000000 0 0 0\nlab0 0002000A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n"
	ipv6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000064 00000000 00000000 00000003 ens3\n"
	default4, default6, err := parseDefaultRouteInterfaces(ipv4, ipv6)
	if err != nil || !default4["ens3"] || !default6["ens3"] || default4["lab0"] {
		t.Fatalf("default route ownership was lost: v4=%v v6=%v err=%v", default4, default6, err)
	}
}

func TestCountInterfacesIgnoresIdleUnmanagedVirtualLinks(t *testing.T) {
	interfaces := []gatewayprotocol.Interface{
		{Name: "lo", StableID: "path:virtual:lo|mac:", Flags: []string{"up", "loopback"}},
		{Name: "ens5", StableID: "path:/sys/devices/pci0000:00/0000:00:05.0|mac:0a", Flags: []string{"up"}, OperState: "up"},
		{Name: "enp2s0", StableID: "path:/sys/devices/pci0000:00/0000:00:06.0|mac:0b", Flags: []string{"up"}, OperState: "down"},
		{Name: "br-8f3d4262125b", StableID: "path:virtual:br-8f3d4262125b|mac:be", Flags: []string{"up"}, OperState: "down"},
		{Name: "lgbr0", StableID: "path:virtual:lgbr0|mac:be", Flags: []string{"up"}, OperState: "down"},
	}
	up, down, idle := countInterfaces(interfaces, map[string]bool{"lgbr0": true})
	if up != 1 || down != 2 || idle != 1 {
		t.Fatalf("up=%d down=%d idle=%d; want a down physical port and the managed lab bridge counted, the Docker bridge ignored", up, down, idle)
	}
}

// A healthy single-arm lab failed `shakerproxy doctor` twice: DHCPv4 was
// "required" although single-arm leaves DHCP to the router, and the running
// lab's own firewall chains counted as a conflict.
func TestDoctorDoesNotFailAHealthySingleArmLab(t *testing.T) {
	singleArm := &networkplan.StagedPlan{Plan: networkplan.Plan{Topology: networkplan.TopologySingleArm, IPv4: networkplan.IPv4Configuration{Enabled: true}}}
	if managedDHCPRequired(gatewayprotocol.ModeRouted, singleArm) {
		t.Fatal("single-arm requires ShakerProxy's DHCPv4")
	}
	bridge := &networkplan.StagedPlan{Plan: networkplan.Plan{Topology: networkplan.TopologyTransparentBridge, IPv4: networkplan.IPv4Configuration{Enabled: true}}}
	if managedDHCPRequired(gatewayprotocol.ModeRouted, bridge) {
		t.Fatal("an inline bridge requires ShakerProxy's DHCPv4")
	}
	routed := &networkplan.StagedPlan{Plan: networkplan.Plan{Topology: networkplan.TopologyTwoNIC, IPv4: networkplan.IPv4Configuration{Enabled: true}}}
	if !managedDHCPRequired(gatewayprotocol.ModeRouted, routed) || managedDHCPRequired(gatewayprotocol.ModeSetupSafe, routed) {
		t.Fatal("a routed lab's DHCPv4 requirement is wrong")
	}

	own := firewall.Inspection{SelectedBackend: "iptables-nft", Issues: []firewall.Issue{{Code: "SHAKERPROXY_CHAIN_CONFLICT", Blocking: true}}}
	if status, notes := firewallDiagnostic(own, true, true); status != gatewayprotocol.DiagnosticPass || notes[1] != "blocking issues: none" {
		t.Fatalf("the running lab's own chains: %s %v", status, notes)
	}
	if status, _ := firewallDiagnostic(own, false, false); status != gatewayprotocol.DiagnosticWarning {
		t.Fatalf("leftover ShakerProxy chains outside routed mode: %s", status)
	}
	foreign := firewall.Inspection{SelectedBackend: "iptables-nft", Issues: []firewall.Issue{{Code: "SHAKERPROXY_CHAIN_CONFLICT", Blocking: true}, {Code: "DOCKER_USER_CHAIN_MISSING", Blocking: true}, {Code: "UFW_ACTIVE", Blocking: false}}}
	if status, notes := firewallDiagnostic(foreign, true, true); status != gatewayprotocol.DiagnosticFail || notes[1] != "blocking issues: DOCKER_USER_CHAIN_MISSING" {
		t.Fatalf("a real blocking issue: %s %v", status, notes)
	}
}
