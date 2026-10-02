package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/conntrack"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkapply"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

// TestBridgeNetlabRole is one step of tests/netlab/bridge-mode.sh, run as
// root inside the ShakerProxy namespace against the real kernel: the plan's
// rendered firewall, bridge netfilter, the traffic policy's DNS redirect and
// conntrack. The script stands in for Netplan (it creates spbr0 with ip).
// It does nothing unless the script sets SHAKERPROXY_BRIDGELAB_ROLE.
func TestBridgeNetlabRole(t *testing.T) {
	role := os.Getenv("SHAKERPROXY_BRIDGELAB_ROLE")
	if role == "" {
		t.Skip("run by tests/netlab/bridge-mode.sh")
	}
	directory := os.Getenv("SHAKERPROXY_BRIDGELAB_DIR")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	plan := networkplan.Plan{
		Schema: networkplan.SchemaVersion, Name: "netlab inline bridge", Topology: networkplan.TopologyTransparentBridge,
		Interfaces: []networkplan.Interface{
			{StableID: "netlab-up", CurrentName: os.Getenv("SHAKERPROXY_BRIDGELAB_UPSTREAM"), Role: networkplan.RoleWAN},
			{StableID: "netlab-device", CurrentName: os.Getenv("SHAKERPROXY_BRIDGELAB_DEVICE"), Role: networkplan.RoleLab},
		},
		Management: networkplan.Management{PreserveActiveSSH: true},
		WAN: networkplan.WANConfiguration{IPv4Mode: networkplan.WANIPv4Static, IPv4Address: "192.168.77.20/24", IPv4Gateway: "192.168.77.1",
			IPv6Mode: networkplan.WANIPv6SLAAC, DNSMode: networkplan.WANDNSUseDHCP, AllowWorkingWANChange: true},
		IPv4: networkplan.IPv4Configuration{Enabled: true, LabCIDR: "192.168.77.0/24", GatewayAddress: "192.168.77.20"},
		IPv6: networkplan.IPv6Configuration{Strategy: networkplan.IPv6ObserveOnly},
	}
	// tests/netlab/bridge-ap-hwsim.sh adds ShakerProxy's Wi-Fi access point
	// (a simulated radio) to the bridge.
	if ap := os.Getenv("SHAKERPROXY_BRIDGELAB_AP"); ap != "" {
		plan.Interfaces = append(plan.Interfaces, networkplan.Interface{StableID: "netlab-ap", CurrentName: ap, Role: networkplan.RoleWiFiAP})
		plan.WiFi = &networkplan.WiFiConfiguration{Enabled: true, SSID: os.Getenv("SHAKERPROXY_BRIDGELAB_SSID"), Security: networkplan.WiFiSecurityWPA2PSK,
			Passphrase: os.Getenv("SHAKERPROXY_BRIDGELAB_PASSPHRASE"), CountryCode: "US", Band: networkplan.WiFiBand24GHz, Channel: 6, BridgeWithLab: true}
	}
	preview := networkplan.BuildPreview(plan, time.Now())
	if !preview.Validation.Valid {
		t.Fatalf("netlab bridge plan is invalid: %+v", preview.Validation.Errors)
	}
	store := &StateStore{state: persistedState{
		OperatingMode: gatewayprotocol.ModeRouted,
		StagedNetworkPlan: &networkplan.StagedPlan{Plan: plan, Preview: preview,
			Transaction: &networktransaction.Record{Phase: networktransaction.PhaseConfirmed}},
	}}
	traffic := &TrafficPolicyManager{
		NetworkState: store, PolicyStore: &trafficpolicy.Store{Path: filepath.Join(directory, "traffic-policy.json")},
		RuntimePath: filepath.Join(directory, "traffic-runtime.json"), Runner: execTrafficCommandRunner{},
		Probe: probeTrafficListener, ProbeIPv6: probeTrafficListenerIPv6, IPv6Available: hostIPv6Available,
	}
	report := func(value any) {
		encoded, _ := json.Marshal(value)
		fmt.Println(string(encoded))
	}
	const iptables, ip6tables = "/usr/sbin/iptables", "/usr/sbin/ip6tables"
	switch role {
	case "apply":
		// The same host steps and order as networkapply.Applier, with the
		// script having built spbr0 in place of Netplan.
		apply, ipv6 := networkapply.OSApplyMachine{}, networkapply.OSIPv6Machine{}
		if err := apply.SetBridgeNFCallIPTables(ctx, 1); err != nil {
			t.Fatal(err)
		}
		if err := apply.SetBridgeNFCallIP6Tables(ctx, 1); err != nil {
			t.Fatal(err)
		}
		if err := apply.LoadShakerProxyFirewall(ctx, iptables, preview.FirewallRestoreIPv4); err != nil {
			t.Fatal(err)
		}
		if err := apply.EnsureShakerProxyAttachments(ctx, iptables, plan.IPv4.NAT44); err != nil {
			t.Fatal(err)
		}
		if err := ipv6.LoadShakerProxyIPv6Firewall(ctx, ip6tables, preview.FirewallRestoreIPv6); err != nil {
			t.Fatal(err)
		}
		if err := ipv6.EnsureShakerProxyIPv6Attachments(ctx, networkapply.IPv6Attachments{Ip6tablesPath: ip6tables, ForwardParent: networkplan.IPv6ForwardParentUser}); err != nil {
			t.Fatal(err)
		}
		if err := traffic.Ensure(ctx); err != nil {
			t.Fatal(err)
		}
		if err := traffic.ReconcileNow(ctx); err != nil {
			t.Fatal(err)
		}
		// The access point's configuration, as the applier writes it to
		// /etc/shakerproxy/hostapd; the script runs hostapd with it.
		if networkplan.WiFiEnabled(plan) {
			config, err := networkplan.RenderHostapdConf(plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "hostapd.conf"), []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		report(map[string]string{"netplan": preview.NetplanYAML, "firewall": preview.FirewallRestoreIPv4, "firewall_ipv6": preview.FirewallRestoreIPv6, "hostapd": preview.HostapdConf})
	case "conntrack":
		scope := labConnectionScope(store, nil)
		listener, err := conntrack.Listen()
		if err != nil {
			t.Fatal(err)
		}
		listenCtx, stop := context.WithTimeout(ctx, 45*time.Second)
		defer stop()
		found := make(chan conntrack.Event, 1)
		if err := os.WriteFile(filepath.Join(directory, "conntrack.ready"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		go func() {
			_ = listener.Run(listenCtx, func(event conntrack.Event) {
				if scope.wants(event) && event.Destination.Port() == 8080 {
					select {
					case found <- event:
					default:
					}
				}
			})
		}()
		select {
		case event := <-found:
			report(map[string]string{"source": event.Source.String(), "destination": event.Destination.String(), "protocol": event.Protocol})
		case <-listenCtx.Done():
			t.Fatal("no bridged connection was reported")
		}
	case "rollback":
		// networkapply.RollbackExecutor's host steps; the script restores
		// the addresses in place of Netplan.
		rollback := networkapply.OSRollbackMachine{}
		// With the plan rolled back there is no lab: the policy reconciles
		// down to its baseline and drops the bridge's DNS redirect.
		store.state = persistedState{OperatingMode: gatewayprotocol.ModeRouted}
		if err := traffic.Ensure(ctx); err != nil {
			t.Fatal(err)
		}
		if err := traffic.ReconcileNow(ctx); err != nil {
			t.Fatal(err)
		}
		if err := rollback.RemoveShakerProxyFirewall(ctx, iptables); err != nil {
			t.Fatal(err)
		}
		if err := (networkapply.OSIPv6Machine{}).RemoveShakerProxyIPv6Firewall(ctx, ip6tables, networkplan.IPv6ForwardParentUser); err != nil {
			t.Fatal(err)
		}
		before := func(name string) int {
			if raw, err := os.ReadFile(filepath.Join(directory, name)); err == nil && len(raw) > 0 && raw[0] == '1' {
				return 1
			}
			return 0
		}
		previous, previous6 := before("bridge-nf.before"), before("bridge-nf6.before")
		if err := rollback.SetBridgeNFCallIPTables(ctx, previous); err != nil {
			t.Fatal(err)
		}
		if err := rollback.SetBridgeNFCallIP6Tables(ctx, previous6); err != nil {
			t.Fatal(err)
		}
		report(map[string]int{"bridge_nf_call_iptables": previous, "bridge_nf_call_ip6tables": previous6})
	default:
		t.Fatalf("unknown role %q", role)
	}
}
