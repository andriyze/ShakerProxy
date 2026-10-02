package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/conntrack"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
	"shakerproxy.dev/shakerproxy/internal/vpn"
	"shakerproxy.dev/shakerproxy/internal/wireguard"
)

// TestVPNNetlabRole is one step of tests/netlab/vpn-mode.sh, run as root
// inside a network namespace against the real kernel: WireGuard over
// netlink, iptables and conntrack. It does nothing unless the script sets
// SHAKERPROXY_VPNLAB_ROLE.
func TestVPNNetlabRole(t *testing.T) {
	role := os.Getenv("SHAKERPROXY_VPNLAB_ROLE")
	if role == "" {
		t.Skip("run by tests/netlab/vpn-mode.sh")
	}
	directory := os.Getenv("SHAKERPROXY_VPNLAB_DIR")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	manager := &VPNManager{
		Store: vpn.Store{Path: filepath.Join(directory, "vpn.json")}, Runner: execTrafficCommandRunner{}, Link: kernelVPNLink{},
		IPv6Available: hostIPv6Available, OutboundAddress: func() string { return os.Getenv("SHAKERPROXY_VPNLAB_ENDPOINT_HOST") }, Logger: logger,
	}
	report := func(value any) {
		encoded, _ := json.Marshal(value)
		fmt.Println(string(encoded))
	}
	switch role {
	case "server-on":
		status, err := manager.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if status, err = manager.Set(ctx, gatewayprotocol.SetVPNParams{ExpectedRevision: status.Revision, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		added, err := manager.AddPeer(ctx, gatewayprotocol.AddVPNPeerParams{Name: "Netlab phone", Actor: "netlab"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "client.conf"), []byte(added.Config), 0o600); err != nil {
			t.Fatal(err)
		}
		// The traffic policy gives VPN devices the lab's DNS rules.
		traffic := netlabTrafficPolicy(t, directory, manager)
		if err := traffic.Ensure(ctx); err != nil {
			t.Fatal(err)
		}
		if err := traffic.ReconcileNow(ctx); err != nil {
			t.Fatal(err)
		}
		status, _ = manager.Status(ctx)
		report(status)
	case "server-conntrack":
		// Prove a VPN device's connection is reported within a second.
		if err := manager.Ensure(ctx); err != nil {
			t.Fatal(err)
		}
		scope := labConnectionScope(nil, manager.TrafficSegment())
		listener, err := conntrack.Listen()
		if err != nil {
			t.Fatal(err)
		}
		listenCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		found := make(chan conntrack.Event, 1)
		if err := os.WriteFile(filepath.Join(directory, "conntrack.ready"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		go func() {
			_ = listener.Run(listenCtx, func(event conntrack.Event) {
				if scope.wants(event) {
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
			t.Fatal("no VPN connection was reported")
		}
	case "server-revoke":
		if err := manager.Ensure(ctx); err != nil {
			t.Fatal(err)
		}
		status, err := manager.Status(ctx)
		if err != nil || len(status.Peers) != 1 {
			t.Fatalf("status %+v %v", status, err)
		}
		if _, err := manager.RevokePeer(ctx, gatewayprotocol.RevokeVPNPeerParams{PeerID: status.Peers[0].ID}); err != nil {
			t.Fatal(err)
		}
		device, err := wireguard.GetDevice(vpn.InterfaceName)
		if err != nil || len(device.Peers) != 0 {
			t.Fatalf("the kernel still has %d peers (%v)", len(device.Peers), err)
		}
		report(map[string]int{"peers": len(device.Peers)})
	case "server-off":
		if err := manager.Ensure(ctx); err != nil {
			t.Fatal(err)
		}
		status, err := manager.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Set(ctx, gatewayprotocol.SetVPNParams{ExpectedRevision: status.Revision, Enabled: false, ListenPort: status.ListenPort, IPv4CIDR: status.IPv4CIDR}); err != nil {
			t.Fatal(err)
		}
		if _, err := wireguard.GetLink(vpn.InterfaceName); !errors.Is(err, wireguard.ErrNotFound) {
			t.Fatalf("wg-lab is still there: %v", err)
		}
	case "client":
		raw, err := os.ReadFile(filepath.Join(directory, "client.conf"))
		if err != nil {
			t.Fatal(err)
		}
		config, err := vpn.ParseClientConfig(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := netlabClient("wgc", config); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown role %q", role)
	}
}

func netlabTrafficPolicy(t *testing.T, directory string, manager *VPNManager) *TrafficPolicyManager {
	t.Helper()
	store, err := OpenStateStore(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &TrafficPolicyManager{
		NetworkState: store, PolicyStore: &trafficpolicy.Store{Path: filepath.Join(directory, "traffic-policy.json")},
		RuntimePath: filepath.Join(directory, "traffic-runtime.json"), Runner: execTrafficCommandRunner{},
		Probe: probeTrafficListener, ProbeIPv6: probeTrafficListenerIPv6, IPv6Available: hostIPv6Available,
		VPN: manager.TrafficSegment,
	}
}

// netlabClient configures a device's side of the tunnel from the
// configuration a tester would scan, as the WireGuard app does.
func netlabClient(name string, config vpn.ClientConfig) error {
	endpoint, err := netip.ParseAddrPort(config.Endpoint)
	if err != nil {
		return fmt.Errorf("the netlab endpoint must be an address: %w", err)
	}
	if err := wireguard.CreateLink(name, vpn.MTU); err != nil {
		return err
	}
	private := [32]byte(config.PrivateKey)
	peer := wireguard.Peer{PublicKey: config.ServerPublicKey, Endpoint: endpoint, Keepalive: config.Keepalive}
	for _, text := range config.AllowedIPs {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, prefix)
	}
	if err := wireguard.Configure(name, wireguard.Config{PrivateKey: &private, Peers: []wireguard.Peer{peer}}); err != nil {
		return err
	}
	for _, address := range config.Addresses {
		if err := wireguard.AddAddress(name, address); err != nil {
			return err
		}
	}
	return wireguard.SetLinkUp(name)
}
