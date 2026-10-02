package daemon

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/conntrack"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
	"shakerproxy.dev/shakerproxy/internal/vpn"
	"shakerproxy.dev/shakerproxy/internal/wireguard"
)

// fakeVPNLink is the kernel: one WireGuard interface, its addresses and the
// forwarding sysctls.
type fakeVPNLink struct {
	mu         sync.Mutex
	link       *wireguard.Link
	device     wireguard.Device
	addresses  []netip.Prefix
	sysctls    map[string]string
	creates    int
	createErr  error
	configures []wireguard.Config
	// configureErr, when set, decides whether a configuration fails.
	configureErr func(wireguard.Config) error
}

func newFakeVPNLink() *fakeVPNLink {
	return &fakeVPNLink{sysctls: map[string]string{"/proc/sys/net/ipv4/ip_forward": "0", "/proc/sys/net/ipv6/conf/all/forwarding": "0"}}
}

func (f *fakeVPNLink) GetLink(name string) (wireguard.Link, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.link == nil || name != vpn.InterfaceName {
		return wireguard.Link{}, wireguard.ErrNotFound
	}
	return *f.link, nil
}

func (f *fakeVPNLink) CreateLink(name string, mtu int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return f.createErr
	}
	f.creates++
	f.link = &wireguard.Link{Index: 9, Kind: "wireguard", MTU: mtu}
	f.device = wireguard.Device{Name: name}
	f.addresses = nil
	return nil
}

func (f *fakeVPNLink) DeleteLink(string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.link, f.device, f.addresses = nil, wireguard.Device{}, nil
	return nil
}

func (f *fakeVPNLink) SetLinkUp(string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.link == nil {
		return wireguard.ErrNotFound
	}
	f.link.Up = true
	return nil
}

func (f *fakeVPNLink) Addresses(string) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Prefix(nil), f.addresses...), nil
}

func (f *fakeVPNLink) AddAddress(_ string, prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addresses = append(f.addresses, prefix)
	return nil
}

func (f *fakeVPNLink) DeleteAddress(_ string, prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addresses = slices.DeleteFunc(f.addresses, func(existing netip.Prefix) bool { return existing == prefix })
	return nil
}

func (f *fakeVPNLink) GetDevice(string) (wireguard.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.link == nil {
		return wireguard.Device{}, wireguard.ErrNotFound
	}
	device := f.device
	device.Peers = append([]wireguard.PeerStatus(nil), f.device.Peers...)
	return device, nil
}

func (f *fakeVPNLink) Configure(_ string, config wireguard.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.link == nil {
		return wireguard.ErrNotFound
	}
	if f.configureErr != nil {
		if err := f.configureErr(config); err != nil {
			return err
		}
	}
	f.configures = append(f.configures, config)
	if config.PrivateKey != nil {
		f.device.PrivateKey = *config.PrivateKey
	}
	if config.ListenPort != 0 {
		f.device.ListenPort = config.ListenPort
	}
	for _, peer := range config.Peers {
		index := slices.IndexFunc(f.device.Peers, func(existing wireguard.PeerStatus) bool { return existing.PublicKey == peer.PublicKey })
		switch {
		case peer.Remove && index >= 0:
			f.device.Peers = slices.Delete(f.device.Peers, index, index+1)
		case peer.Remove:
		case index >= 0:
			f.device.Peers[index].AllowedIPs = peer.AllowedIPs
		default:
			f.device.Peers = append(f.device.Peers, wireguard.PeerStatus{PublicKey: peer.PublicKey, AllowedIPs: peer.AllowedIPs})
		}
	}
	return nil
}

func (f *fakeVPNLink) ReadSysctl(path string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.sysctls[path]
	if !ok {
		return "", os.ErrNotExist
	}
	return value, nil
}

func (f *fakeVPNLink) WriteSysctl(path, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sysctls[path] = value
	return nil
}

func (f *fakeVPNLink) peers() []wireguard.PeerStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]wireguard.PeerStatus(nil), f.device.Peers...)
}

type vpnFixture struct {
	manager *VPNManager
	link    *fakeVPNLink
	runner  *fakeTrafficRunner
	changes *int
}

func newVPNFixture(t *testing.T, network *StateStore) vpnFixture {
	t.Helper()
	link := newFakeVPNLink()
	// Docker's DOCKER-USER, with the traffic policy's security hook first and
	// ShakerProxy's lab forward chain below it.
	runner := &fakeTrafficRunner{chains: map[string]bool{"DOCKER-USER": true, "6:DOCKER-USER": true}}
	runner.attach("", "DOCKER-USER", securityForwardChain, 1)
	runner.attach("", "DOCKER-USER", "SHAKERPROXY-FORWARD", 2)
	changes := 0
	manager := &VPNManager{
		Store: vpn.Store{Path: filepath.Join(t.TempDir(), "vpn.json")}, NetworkState: network, Runner: runner, Link: link,
		IPv6Available: func() bool { return true }, OutboundAddress: func() string { return "192.168.10.177" },
		Changed: func() { changes++ },
		Now:     func() time.Time { return time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) },
	}
	return vpnFixture{manager: manager, link: link, runner: runner, changes: &changes}
}

func (f vpnFixture) turnOn(t *testing.T, change func(*gatewayprotocol.SetVPNParams)) gatewayprotocol.VPNStatus {
	t.Helper()
	current, err := f.manager.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	params := gatewayprotocol.SetVPNParams{ExpectedRevision: current.Revision, Enabled: true, ListenPort: current.ListenPort, Endpoint: current.EndpointSetting, IPv4CIDR: current.IPv4CIDR, AllowPeerToPeer: current.AllowPeerToPeer}
	if change != nil {
		change(&params)
	}
	status, err := f.manager.Set(t.Context(), params)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func TestVPNModeIsOffAndListensNowhereUntilTurnedOn(t *testing.T) {
	fixture := newVPNFixture(t, nil)
	if err := fixture.manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	if fixture.link.creates != 0 || fixture.runner.restores() != 0 {
		t.Fatalf("VPN mode off created %d interfaces and %d firewall batches", fixture.link.creates, fixture.runner.restores())
	}
	status, err := fixture.manager.Status(t.Context())
	if err != nil || status.Enabled || status.Up || len(status.Peers) != 0 || status.ListenPort != 51820 || status.IPv4CIDR != "10.89.0.0/24" {
		t.Fatalf("status = %+v, %v", status, err)
	}
	if _, ok := fixture.manager.Segment(); ok {
		t.Fatal("an off VPN has a segment")
	}
	if _, err := fixture.manager.AddPeer(t.Context(), gatewayprotocol.AddVPNPeerParams{Name: "Pixel"}); err == nil || !strings.Contains(err.Error(), "turn it on") {
		t.Fatalf("a device was added while VPN mode is off: %v", err)
	}
	info, err := os.Stat(fixture.manager.Store.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the server key is not root-only: %v %v", info, err)
	}
}

func TestVPNModeComesUpBelowTheSecurityChains(t *testing.T) {
	fixture := newVPNFixture(t, nil)
	status := fixture.turnOn(t, nil)
	if !status.Up || status.Endpoint != "192.168.10.177:51820" || status.Revision != 1 || *fixture.changes == 0 {
		t.Fatalf("status = %+v (changes %d)", status, *fixture.changes)
	}
	link := fixture.link
	if link.link == nil || !link.link.Up || link.link.MTU != vpn.MTU || link.device.ListenPort != 51820 || link.sysctls["/proc/sys/net/ipv4/ip_forward"] != "1" {
		t.Fatalf("interface = %+v device port %d forwarding %q", link.link, link.device.ListenPort, link.sysctls["/proc/sys/net/ipv4/ip_forward"])
	}
	state, _ := fixture.manager.Store.Load()
	if link.device.PrivateKey != state.PrivateKey || status.ServerPublicKey != state.PrivateKey.PublicKey().String() {
		t.Fatal("the interface does not use the stored server key")
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.89.0.1/24"), netip.PrefixFrom(state.GatewayIPv6(), 64)}
	if !samePrefixes(link.addresses, want) {
		t.Fatalf("addresses = %v, want %v", link.addresses, want)
	}
	// The security chain's blocks see VPN traffic before the VPN accepts it.
	if got := fixture.runner.positions("", "DOCKER-USER"); !slices.Equal(got, []string{securityForwardChain, vpn.ForwardChain, "SHAKERPROXY-FORWARD"}) {
		t.Fatalf("DOCKER-USER = %v", got)
	}
	if got := fixture.runner.positions("6:", "DOCKER-USER"); !slices.Equal(got, []string{vpn.ForwardChain}) {
		t.Fatalf("ip6tables DOCKER-USER = %v", got)
	}
	for _, prefix := range []string{"", "6:"} {
		if !slices.Contains(fixture.runner.positions(prefix, "INPUT"), vpn.InputChain) || !slices.Contains(fixture.runner.positions(prefix, "POSTROUTING"), vpn.PostroutingChain) {
			t.Fatalf("%s hooks: INPUT %v POSTROUTING %v", prefix, fixture.runner.positions(prefix, "INPUT"), fixture.runner.positions(prefix, "POSTROUTING"))
		}
	}
	if batch := fixture.runner.lastRestore(iptablesRestoreBinary); !strings.Contains(batch, "-A SHAKERPROXY-VPN-FORWARD -i wg-lab -j ACCEPT") || !strings.Contains(batch, "-s 10.89.0.0/24 ! -o wg-lab -j MASQUERADE") {
		t.Fatalf("IPv4 batch:\n%s", batch)
	}
	// Reconciling an unchanged VPN rewrites nothing and keeps sessions.
	restores, configures := fixture.runner.restores(), len(link.configures)
	fixture.manager.reconcile(t.Context())
	if fixture.runner.restores() != restores || len(link.configures) != configures || link.creates != 1 {
		t.Fatalf("an unchanged VPN was rewritten: restores %d→%d configures %d→%d creates %d", restores, fixture.runner.restores(), configures, len(link.configures), link.creates)
	}
	// A flushed chain is repaired by the next reconcile.
	fixture.runner.flush("", vpn.ForwardChain)
	fixture.manager.reconcile(t.Context())
	if fixture.runner.restores() == restores {
		t.Fatal("a flushed VPN chain was not restored")
	}
	segment := fixture.manager.TrafficSegment()
	if segment == nil || segment.Interface != "wg-lab" || segment.IPv4CIDR != "10.89.0.0/24" || segment.GatewayIPv4 != "10.89.0.1" {
		t.Fatalf("segment = %+v", segment)
	}
}

func TestVPNDevicesAreAddedNamedAndRevoked(t *testing.T) {
	fixture := newVPNFixture(t, nil)
	fixture.turnOn(t, nil)
	added, err := fixture.manager.AddPeer(t.Context(), gatewayprotocol.AddVPNPeerParams{Name: "Pixel", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if added.Peer.IPv4 != "10.89.0.2" || added.FileName != "pixel.conf" || !strings.Contains(added.Config, "Endpoint = 192.168.10.177:51820\n") || !strings.Contains(added.Config, "DNS = 10.89.0.1\n") {
		t.Fatalf("added = %+v", added)
	}
	config, err := vpn.ParseClientConfig(added.Config)
	if err != nil {
		t.Fatal(err)
	}
	peers := fixture.link.peers()
	if len(peers) != 1 || vpn.Key(peers[0].PublicKey) != config.PrivateKey.PublicKey() || len(peers[0].AllowedIPs) != 2 || peers[0].AllowedIPs[0].String() != "10.89.0.2/32" {
		t.Fatalf("kernel peers = %+v", peers)
	}
	raw, _ := os.ReadFile(fixture.manager.Store.Path)
	if strings.Contains(string(raw), config.PrivateKey.String()) {
		t.Fatal("the device's private key was stored")
	}
	if _, err := fixture.manager.AddPeer(t.Context(), gatewayprotocol.AddVPNPeerParams{Name: "pixel"}); err == nil {
		t.Fatal("a second device with the same name was added")
	}
	if _, err := fixture.manager.SetPeerDevice(gatewayprotocol.SetVPNPeerDeviceParams{PeerID: added.Peer.ID, DeviceID: "device-0123456789abcdef0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	segment := fixture.manager.TrafficSegment()
	if match := segment.Devices["device-0123456789abcdef0123456789abcdef"]; !slices.Equal(match.IPv4, []string{"10.89.0.2"}) || len(match.HardwareAddresses) != 0 {
		t.Fatalf("device match = %+v", match)
	}

	// The kernel refuses the removal: the revocation is saved anyway, so
	// the device never comes back, and the next reconcile removes it.
	fixture.link.configureErr = func(config wireguard.Config) error {
		if len(config.Peers) == 1 && config.Peers[0].Remove {
			return errors.New("netlink busy")
		}
		return nil
	}
	if _, err := fixture.manager.RevokePeer(t.Context(), gatewayprotocol.RevokeVPNPeerParams{PeerID: added.Peer.ID}); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoke error = %v", err)
	}
	if state, _ := fixture.manager.Store.Load(); len(state.Peers) != 0 {
		t.Fatal("the revocation was not saved")
	}
	fixture.link.configureErr = nil
	fixture.manager.reconcile(t.Context())
	if len(fixture.link.peers()) != 0 {
		t.Fatal("the reconcile left the revoked device on the interface")
	}
	// The next device gets a fresh address.
	next, err := fixture.manager.AddPeer(t.Context(), gatewayprotocol.AddVPNPeerParams{Name: "Laptop"})
	if err != nil || next.Peer.IPv4 != "10.89.0.3" {
		t.Fatalf("next device %+v %v", next.Peer, err)
	}
	if _, err := fixture.manager.RevokePeer(t.Context(), gatewayprotocol.RevokeVPNPeerParams{PeerID: next.Peer.ID}); err != nil || len(fixture.link.peers()) != 0 {
		t.Fatalf("revoke %v peers %d", err, len(fixture.link.peers()))
	}
}

func TestAFailedVPNChangeKeepsThePreviousVPN(t *testing.T) {
	fixture := newVPNFixture(t, nil)
	fixture.turnOn(t, nil)
	fixture.link.configureErr = func(config wireguard.Config) error {
		if config.ListenPort == 4500 {
			return syscall.EADDRINUSE
		}
		return nil
	}
	current, _ := fixture.manager.Status(t.Context())
	_, err := fixture.manager.Set(t.Context(), gatewayprotocol.SetVPNParams{ExpectedRevision: current.Revision, Enabled: true, ListenPort: 4500, IPv4CIDR: current.IPv4CIDR})
	if err == nil || !strings.Contains(err.Error(), "UDP port 4500 is already in use") {
		t.Fatalf("error = %v", err)
	}
	after, _ := fixture.manager.Status(t.Context())
	if after.Revision != current.Revision || after.ListenPort != 51820 || !after.Up || fixture.link.device.ListenPort != 51820 {
		t.Fatalf("after a failed change: %+v (kernel port %d)", after, fixture.link.device.ListenPort)
	}
	if _, err := fixture.manager.Set(t.Context(), gatewayprotocol.SetVPNParams{ExpectedRevision: 0, Enabled: true}); err == nil || !strings.Contains(err.Error(), "changed meanwhile") {
		t.Fatalf("a stale revision was accepted: %v", err)
	}

	// Turning off removes the interface and every VPN hook.
	if _, err := fixture.manager.Set(t.Context(), gatewayprotocol.SetVPNParams{ExpectedRevision: after.Revision, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if fixture.link.link != nil || slices.Contains(fixture.runner.positions("", "DOCKER-USER"), vpn.ForwardChain) || slices.Contains(fixture.runner.positions("", "INPUT"), vpn.InputChain) {
		t.Fatalf("VPN mode off left %+v and DOCKER-USER %v", fixture.link.link, fixture.runner.positions("", "DOCKER-USER"))
	}
	if fixture.manager.TrafficSegment() != nil {
		t.Fatal("VPN mode off still has a segment")
	}
}

func TestVPNModeExplainsAKernelWithoutWireGuard(t *testing.T) {
	fixture := newVPNFixture(t, nil)
	fixture.link.createErr = wireguard.ErrUnsupported
	current, _ := fixture.manager.Status(t.Context())
	_, err := fixture.manager.Set(t.Context(), gatewayprotocol.SetVPNParams{ExpectedRevision: current.Revision, Enabled: true})
	if err == nil || !strings.Contains(err.Error(), "no WireGuard support") {
		t.Fatalf("error = %v", err)
	}
	if state, _ := fixture.manager.Store.Load(); state.Settings.Enabled {
		t.Fatal("a VPN that could not come up was saved as on")
	}
	if slices.Contains(fixture.runner.positions("", "DOCKER-USER"), vpn.ForwardChain) {
		t.Fatal("a failed enable left the VPN hook")
	}
}

func TestVPNNetworkMustNotOverlapTheLab(t *testing.T) {
	network := routedTrafficState()
	network.state.StagedNetworkPlan.Plan.IPv4.LabCIDR = "10.89.0.0/16"
	fixture := newVPNFixture(t, network)
	current, _ := fixture.manager.Status(t.Context())
	if _, err := fixture.manager.Set(t.Context(), gatewayprotocol.SetVPNParams{ExpectedRevision: current.Revision, Enabled: true}); err == nil || !strings.Contains(err.Error(), "overlaps the lab") {
		t.Fatalf("an overlapping VPN network was accepted: %v", err)
	}
	status := fixture.turnOn(t, func(params *gatewayprotocol.SetVPNParams) { params.IPv4CIDR = "10.90.0.0/24" })
	if !status.Up || status.GatewayIPv4 != "10.90.0.1" {
		t.Fatalf("status = %+v", status)
	}
}

func TestVPNSegmentDisappearsDuringEmergencyBypass(t *testing.T) {
	network := routedTrafficState()
	fixture := newVPNFixture(t, network)
	fixture.turnOn(t, nil)
	if fixture.manager.TrafficSegment() == nil {
		t.Fatal("no segment while up")
	}
	network.state.EmergencyBypass = true
	if fixture.manager.TrafficSegment() != nil {
		t.Fatal("VPN traffic is still inspected during an emergency bypass")
	}
}

func TestTrafficPolicyGivesVPNDevicesTheLabRules(t *testing.T) {
	root := t.TempDir()
	runner := &fakeTrafficRunner{chains: map[string]bool{"DOCKER-USER": true}}
	segment := &trafficpolicy.Segment{Interface: "wg-lab", IPv4CIDR: "10.89.0.0/24", GatewayIPv4: "10.89.0.1", IPv6Prefix: "fd12:3456:789a:1::/64", GatewayIPv6: "fd12:3456:789a:1::1"}
	manager := &TrafficPolicyManager{
		NetworkState: &StateStore{}, PolicyStore: &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")}, RuntimePath: filepath.Join(root, "runtime.json"),
		Runner: runner, Probe: func(context.Context, int) error { return nil }, VPN: func() *trafficpolicy.Segment { return segment },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	// A VPN-only appliance: no lab plan, the VPN is the lab.
	if err := manager.ReconcileNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	batch := runner.lastRestore(iptablesRestoreBinary)
	for _, want := range []string{
		"-A SHAKERPROXY-SEC-PREROUTING -i wg-lab -s 10.89.0.0/24 -d 10.89.0.1 -p udp --dport 53 -j REDIRECT --to-ports 1053",
		"-A SHAKERPROXY-SEC-PREROUTING -i wg-lab -s 10.89.0.0/24 ! -d 10.89.0.0/24 -p tcp --dport 53 -j REDIRECT --to-ports 1053",
		"-A SHAKERPROXY-SEC-INPUT -i wg-lab -s 10.89.0.0/24 -p udp --dport 1053 -m conntrack --ctstate DNAT -j ACCEPT",
	} {
		if !strings.Contains(batch, want) {
			t.Fatalf("batch lacks %q:\n%s", want, batch)
		}
	}
	runtime, err := os.ReadFile(manager.RuntimePath)
	if err != nil || !strings.Contains(string(runtime), "10.89.0.0/24") {
		t.Fatalf("the DNS forwarder does not accept VPN clients: %s %v", runtime, err)
	}
}

func TestVPNConnectionsAreReported(t *testing.T) {
	segment := &trafficpolicy.Segment{Interface: "wg-lab", IPv4CIDR: "10.89.0.0/24", GatewayIPv4: "10.89.0.1", IPv6Prefix: "fd12:3456:789a:1::/64", GatewayIPv6: "fd12:3456:789a:1::1"}
	scope := labConnectionScope(singleArmLabStore(), segment)
	for _, check := range []struct {
		event conntrack.Event
		want  bool
	}{
		{connectionEvent("tcp", "10.89.0.2:41000", "140.82.121.4:443"), true},
		{connectionEvent("udp", "[fd12:3456:789a:1::2]:41000", "[2606:4700::1111]:443"), true},
		{connectionEvent("udp", "10.89.0.2:41000", "10.89.0.1:53"), false},
		{connectionEvent("tcp", "192.168.10.201:37064", "140.82.121.4:443"), true},
	} {
		if got := scope.wants(check.event); got != check.want {
			t.Fatalf("%v → %v: wants = %v", check.event.Source, check.event.Destination, got)
		}
	}
	if labConnectionScope(nil, segment) == nil {
		t.Fatal("a VPN-only appliance reports no connections")
	}
}

func TestVPNRecordingRunsBesideTheLabRecording(t *testing.T) {
	fixture := newLabRecordingFixture(t)
	segment := &trafficpolicy.Segment{Interface: "wg-lab", IPv4CIDR: "10.89.0.0/24", GatewayIPv4: "10.89.0.1"}
	vpnRecorder := fixture.newRecorder(t)
	vpnRecorder.Source = nil
	vpnRecorder.VPN = func() *trafficpolicy.Segment { return segment }
	lab := fixture.recorder.Tick(t.Context())
	recording := vpnRecorder.Tick(t.Context())
	if !lab.Recording || !recording.Recording || lab.SessionID == recording.SessionID {
		t.Fatalf("lab %+v VPN %+v", lab, recording)
	}
	views := fixture.sessions(t)
	interfaces := map[string]string{}
	for _, view := range views {
		if view.Active {
			interfaces[view.Session.Source.InterfaceName] = view.Session.Request.Name
		}
	}
	if interfaces["ens18"] != capture.LabRecordingName || interfaces["wg-lab"] != capture.VPNRecordingName {
		t.Fatalf("active recordings = %v", interfaces)
	}
	// Each recorder keeps its own: a second tick changes nothing.
	if again := vpnRecorder.Tick(t.Context()); again.SessionID != recording.SessionID {
		t.Fatalf("the VPN recording restarted: %+v", again)
	}
	if again := fixture.recorder.Tick(t.Context()); again.SessionID != lab.SessionID {
		t.Fatalf("the lab recording restarted: %+v", again)
	}
	// VPN mode off stops only the VPN recording.
	segment = nil
	if stopped := vpnRecorder.Tick(t.Context()); stopped.Recording {
		t.Fatalf("VPN off: %+v", stopped)
	}
	if fixture.units.active[recording.SessionID] || !fixture.units.active[lab.SessionID] {
		t.Fatalf("units = %v", fixture.units.active)
	}
}
