package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/policycoordination"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
	"shakerproxy.dev/shakerproxy/internal/vpn"
	"shakerproxy.dev/shakerproxy/internal/wireguard"
)

// vpnConnectedWithin is how recent a handshake must be for a VPN device to
// count as connected; an active WireGuard session rekeys every two minutes.
const vpnConnectedWithin = 3 * time.Minute

// vpnLink is the kernel side of the VPN; tests replace it.
type vpnLink interface {
	GetLink(name string) (wireguard.Link, error)
	CreateLink(name string, mtu int) error
	DeleteLink(name string) error
	SetLinkUp(name string) error
	Addresses(name string) ([]netip.Prefix, error)
	AddAddress(name string, prefix netip.Prefix) error
	DeleteAddress(name string, prefix netip.Prefix) error
	GetDevice(name string) (wireguard.Device, error)
	Configure(name string, config wireguard.Config) error
	ReadSysctl(path string) (string, error)
	WriteSysctl(path, value string) error
}

type kernelVPNLink struct{}

func (kernelVPNLink) GetLink(name string) (wireguard.Link, error) { return wireguard.GetLink(name) }
func (kernelVPNLink) CreateLink(name string, mtu int) error       { return wireguard.CreateLink(name, mtu) }
func (kernelVPNLink) DeleteLink(name string) error                { return wireguard.DeleteLink(name) }
func (kernelVPNLink) SetLinkUp(name string) error                 { return wireguard.SetLinkUp(name) }
func (kernelVPNLink) Addresses(name string) ([]netip.Prefix, error) {
	return wireguard.Addresses(name)
}
func (kernelVPNLink) AddAddress(name string, prefix netip.Prefix) error {
	return wireguard.AddAddress(name, prefix)
}
func (kernelVPNLink) DeleteAddress(name string, prefix netip.Prefix) error {
	return wireguard.DeleteAddress(name, prefix)
}
func (kernelVPNLink) GetDevice(name string) (wireguard.Device, error) {
	return wireguard.GetDevice(name)
}
func (kernelVPNLink) Configure(name string, config wireguard.Config) error {
	return wireguard.Configure(name, config)
}
func (kernelVPNLink) ReadSysctl(path string) (string, error) {
	raw, err := os.ReadFile(path)
	return strings.TrimSpace(string(raw)), err
}
func (kernelVPNLink) WriteSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value+"\n"), 0o644)
}

// VPNManager runs VPN mode: the wg-lab WireGuard interface, its devices
// and its firewall chains. It is a client segment of its own, beside the
// confirmed lab plan or without one, and it applies transactionally: a
// change that cannot be applied leaves the previous VPN running (or none).
// VPN mode is off until an administrator turns it on; nothing listens
// before then.
type VPNManager struct {
	Store        vpn.Store
	NetworkState *StateStore
	Runner       trafficCommandRunner
	Link         vpnLink
	// CoordinationLockPath serializes firewall changes with the traffic
	// policy, whose security chains must stay in front of the VPN's.
	CoordinationLockPath string
	IPv6Available        func() bool
	// OutboundAddress returns the IPv4 address this host reaches the
	// internet from; it is the default address devices connect to.
	OutboundAddress func() string
	// Changed runs after the VPN segment appears, changes or goes away.
	Changed func()
	Logger  *slog.Logger
	Now     func() time.Time

	mu      sync.Mutex
	segment atomic.Pointer[vpnRuntime]
	problem atomic.Pointer[string]
	// installed caches each firewall batch and the chains' listing after
	// it, so the 15 s reconcile does not rewrite unchanged rules.
	installed map[string]installedSecurityBatch
	lastWarn  string
}

// vpnRuntime is what other parts of gatewayd see of a running VPN.
type vpnRuntime struct {
	state      vpn.State
	ipv6Routed bool
}

func NewProductionVPNManager(networkState *StateStore, statePath, coordinationLockPath string, logger *slog.Logger) *VPNManager {
	return &VPNManager{
		Store:                vpn.Store{Path: statePath},
		NetworkState:         networkState,
		Runner:               execTrafficCommandRunner{},
		Link:                 kernelVPNLink{},
		CoordinationLockPath: coordinationLockPath,
		IPv6Available:        hostIPv6Available,
		OutboundAddress:      outboundIPv4,
		Logger:               logger,
	}
}

// Ensure brings VPN mode to its saved state at startup: up when enabled,
// fully removed when not. A failure is retried by the reconcile loop.
func (m *VPNManager) Ensure(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.Store.Load()
	if err != nil {
		return err
	}
	if !state.Settings.Enabled {
		return m.teardownLocked(ctx)
	}
	return m.applyLocked(ctx, state)
}

// Run reconciles every 15 s until ctx ends, so a deleted interface,
// flushed chain or reboot-reordered hook is repaired.
func (m *VPNManager) Run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		m.reconcile(ctx)
	}
}

func (m *VPNManager) reconcile(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.Store.Load()
	if err != nil {
		m.warn("the VPN state cannot be read", err)
		return
	}
	if !state.Settings.Enabled {
		return
	}
	if err := m.applyLocked(ctx, state); err != nil {
		m.warn("VPN mode is on but could not be brought up; retrying", err)
		return
	}
	m.lastWarn = ""
}

// Segment returns the running VPN's client network for the traffic policy,
// connection reporting and recording, or false while VPN mode is off or
// down.
func (m *VPNManager) Segment() (vpn.State, bool) {
	if m == nil {
		return vpn.State{}, false
	}
	runtime := m.segment.Load()
	if runtime == nil {
		return vpn.State{}, false
	}
	return runtime.state, true
}

// TrafficSegment is the VPN as a traffic-policy client segment: devices
// are matched by their VPN addresses, which WireGuard binds to their keys.
//
// During an emergency bypass there is none: VPN devices keep routing, NATed,
// but nothing inspects, redirects or records their traffic.
func (m *VPNManager) TrafficSegment() *trafficpolicy.Segment {
	state, ok := m.Segment()
	if !ok || m.NetworkState != nil && m.NetworkState.Get().EmergencyBypass {
		return nil
	}
	segment := &trafficpolicy.Segment{
		Interface:   vpn.InterfaceName,
		IPv4CIDR:    state.IPv4Prefix().String(),
		GatewayIPv4: state.GatewayIPv4().String(),
		IPv6Prefix:  state.IPv6PrefixValue().String(),
		GatewayIPv6: state.GatewayIPv6().String(),
		Devices:     map[string]trafficpolicy.DeviceMatch{},
	}
	for _, peer := range state.Peers {
		if peer.DeviceID == "" {
			continue
		}
		match := segment.Devices[peer.DeviceID]
		match.IPv4 = append(match.IPv4, peer.IPv4)
		match.IPv6 = append(match.IPv6, peer.IPv6)
		segment.Devices[peer.DeviceID] = match
	}
	return segment
}

// Status answers GetVPN.
func (m *VPNManager) Status(ctx context.Context) (gatewayprotocol.VPNStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.Store.Load()
	if err != nil {
		return gatewayprotocol.VPNStatus{}, err
	}
	return m.statusLocked(state), nil
}

func (m *VPNManager) statusLocked(state vpn.State) gatewayprotocol.VPNStatus {
	settings := state.Settings
	status := gatewayprotocol.VPNStatus{
		Schema: 1, Revision: state.Revision, Enabled: settings.Enabled, Interface: vpn.InterfaceName,
		ListenPort: settings.ListenPort, EndpointSetting: settings.Endpoint, DefaultEndpointHost: m.defaultHost(),
		ServerPublicKey: state.PrivateKey.PublicKey().String(), IPv4CIDR: settings.IPv4CIDR,
		GatewayIPv4: state.GatewayIPv4().String(), IPv6Prefix: state.IPv6Prefix, GatewayIPv6: state.GatewayIPv6().String(),
		AllowPeerToPeer: settings.AllowPeerToPeer, Peers: []gatewayprotocol.VPNPeerStatus{}, Notes: []string{},
	}
	status.Endpoint, _ = settings.EffectiveEndpoint(status.DefaultEndpointHost)
	runtime := m.segment.Load()
	status.Up = settings.Enabled && runtime != nil
	if runtime != nil {
		status.IPv6Routed = runtime.ipv6Routed
	}
	if problem := m.problem.Load(); settings.Enabled && !status.Up && problem != nil {
		status.Problem = *problem
	}
	var kernel map[vpn.Key]wireguard.PeerStatus
	if status.Up {
		if device, err := m.Link.GetDevice(vpn.InterfaceName); err == nil {
			kernel = map[vpn.Key]wireguard.PeerStatus{}
			for _, peer := range device.Peers {
				kernel[vpn.Key(peer.PublicKey)] = peer
			}
		}
	}
	now := m.now()
	for _, peer := range state.SortedPeers() {
		item := peerStatus(peer)
		if live, ok := kernel[peer.PublicKey]; ok {
			item.ReceivedBytes, item.SentBytes = live.RxBytes, live.TxBytes
			if live.Endpoint.IsValid() {
				item.RemoteAddress = live.Endpoint.String()
			}
			if !live.LastHandshake.IsZero() {
				handshake := live.LastHandshake
				item.LastHandshake = &handshake
				item.Connected = now.Sub(handshake) < vpnConnectedWithin
			}
		}
		status.Peers = append(status.Peers, item)
	}
	if settings.Enabled {
		_, port, _ := vpn.SplitEndpoint(status.Endpoint)
		status.Notes = append(status.Notes,
			fmt.Sprintf("Devices connect to %s. To use the VPN from outside this network, forward UDP port %d on your router to this appliance and set the VPN address to your public address or name.", orText(status.Endpoint, "this appliance"), orPort(port, settings.ListenPort)),
		)
		if settings.AllowPeerToPeer {
			status.Notes = append(status.Notes, "VPN devices reach the internet, the networks behind ShakerProxy and each other, but not ShakerProxy's management page.")
		} else {
			status.Notes = append(status.Notes, "VPN devices reach the internet and the networks behind ShakerProxy, but not each other or ShakerProxy's management page.")
		}
		if status.IPv6Routed {
			status.Notes = append(status.Notes, "IPv6 is routed: devices get a private IPv6 address and reach IPv6 sites through ShakerProxy (NAT66).")
		} else {
			status.Notes = append(status.Notes, "IPv6 stays inside the tunnel (this host does not forward IPv6), so devices use IPv4 for everything and nothing bypasses ShakerProxy.")
		}
	}
	return status
}

func orText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func orPort(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func peerStatus(peer vpn.Peer) gatewayprotocol.VPNPeerStatus {
	return gatewayprotocol.VPNPeerStatus{
		ID: peer.ID, Name: peer.Name, DeviceID: peer.DeviceID, PublicKey: peer.PublicKey.String(),
		IPv4: peer.IPv4, IPv6: peer.IPv6, CreatedAt: peer.CreatedAt, CreatedBy: peer.CreatedBy,
	}
}

// Set turns VPN mode on or off and changes its settings.
func (m *VPNManager) Set(ctx context.Context, params gatewayprotocol.SetVPNParams) (gatewayprotocol.VPNStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.Store.Load()
	if err != nil {
		return gatewayprotocol.VPNStatus{}, err
	}
	if params.ExpectedRevision != current.Revision {
		return gatewayprotocol.VPNStatus{}, fmt.Errorf("the VPN settings changed meanwhile (revision %d, expected %d); reload and try again", current.Revision, params.ExpectedRevision)
	}
	settings, err := vpn.Settings{
		Enabled: params.Enabled, ListenPort: params.ListenPort, Endpoint: params.Endpoint,
		IPv4CIDR: params.IPv4CIDR, AllowPeerToPeer: params.AllowPeerToPeer,
	}.Normalize()
	if err != nil {
		return gatewayprotocol.VPNStatus{}, err
	}
	if settings.IPv4CIDR != current.Settings.IPv4CIDR && len(current.Peers) != 0 {
		return gatewayprotocol.VPNStatus{}, errors.New("the VPN network cannot change while devices use it; revoke them first")
	}
	if settings.Enabled {
		if err := m.checkNetworkFree(settings.IPv4CIDR); err != nil {
			return gatewayprotocol.VPNStatus{}, err
		}
	}
	candidate := current
	candidate.Settings = settings
	candidate.Revision++
	if err := m.switchLocked(ctx, current, candidate); err != nil {
		return gatewayprotocol.VPNStatus{}, err
	}
	m.log("VPN settings applied", "enabled", settings.Enabled, "listen_port", settings.ListenPort, "revision", candidate.Revision)
	return m.statusLocked(candidate), nil
}

// switchLocked moves the running VPN from current to candidate and saves
// candidate. On any failure the previous VPN is restored (or removed when
// it was off) and nothing is saved.
func (m *VPNManager) switchLocked(ctx context.Context, current, candidate vpn.State) error {
	var applyErr error
	if candidate.Settings.Enabled {
		applyErr = m.applyLocked(ctx, candidate)
	} else {
		applyErr = m.teardownLocked(ctx)
	}
	if applyErr == nil {
		if applyErr = m.Store.Save(candidate); applyErr == nil {
			m.changed()
			return nil
		}
	}
	restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	var restoreErr error
	if current.Settings.Enabled {
		restoreErr = m.applyLocked(restoreCtx, current)
	} else {
		restoreErr = m.teardownLocked(restoreCtx)
	}
	m.changed()
	if restoreErr != nil {
		return errors.Join(applyErr, fmt.Errorf("restoring the previous VPN also failed: %w", restoreErr))
	}
	return applyErr
}

// checkNetworkFree refuses a VPN network that overlaps the lab or any
// network already on this host.
func (m *VPNManager) checkNetworkFree(cidr string) error {
	prefix := netip.MustParsePrefix(cidr)
	if _, plan, ok := confirmedLabPlan(m.NetworkState); ok {
		if lab, err := netip.ParsePrefix(plan.IPv4.LabCIDR); err == nil && lab.Masked().Overlaps(prefix) {
			return fmt.Errorf("the VPN network %s overlaps the lab network %s; choose another, such as 10.89.0.0/24", cidr, lab.Masked())
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range interfaces {
		if iface.Name == vpn.InterfaceName {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			network, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(network.IP)
			if !ok || !ip.Unmap().Is4() {
				continue
			}
			bits, _ := network.Mask.Size()
			if netip.PrefixFrom(ip.Unmap(), bits).Masked().Overlaps(prefix) {
				return fmt.Errorf("the VPN network %s overlaps %s on %s; choose another", cidr, network.String(), iface.Name)
			}
		}
	}
	return nil
}

// AddPeer adds a device and returns its one-time configuration.
func (m *VPNManager) AddPeer(ctx context.Context, params gatewayprotocol.AddVPNPeerParams) (gatewayprotocol.VPNPeerConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.Store.Load()
	if err != nil {
		return gatewayprotocol.VPNPeerConfig{}, err
	}
	if !state.Settings.Enabled {
		return gatewayprotocol.VPNPeerConfig{}, errors.New("VPN mode is off; turn it on first")
	}
	name, err := vpn.ValidateName(params.Name)
	if err != nil {
		return gatewayprotocol.VPNPeerConfig{}, err
	}
	for _, peer := range state.Peers {
		if strings.EqualFold(peer.Name, name) {
			return gatewayprotocol.VPNPeerConfig{}, fmt.Errorf("a VPN device is already called %q; revoke it or choose another name", peer.Name)
		}
	}
	endpoint, err := state.Settings.EffectiveEndpoint(m.defaultHost())
	if err != nil {
		return gatewayprotocol.VPNPeerConfig{}, err
	}
	address4, address6, offset, err := state.NextAddresses()
	if err != nil {
		return gatewayprotocol.VPNPeerConfig{}, err
	}
	privateKey, err := vpn.NewPrivateKey()
	if err != nil {
		return gatewayprotocol.VPNPeerConfig{}, err
	}
	id, err := vpn.NewPeerID()
	if err != nil {
		return gatewayprotocol.VPNPeerConfig{}, err
	}
	actor := strings.TrimSpace(params.Actor)
	if len(actor) > 96 {
		actor = actor[:96]
	}
	peer := vpn.Peer{ID: id, Name: name, PublicKey: privateKey.PublicKey(), IPv4: address4.String(), IPv6: address6.String(), CreatedAt: m.now(), CreatedBy: actor}
	config, err := vpn.DeviceConfig(state, peer, privateKey, endpoint)
	if err != nil {
		return gatewayprotocol.VPNPeerConfig{}, err
	}
	candidate := state
	candidate.Peers = append(append([]vpn.Peer(nil), state.Peers...), peer)
	candidate.NextHost = offset + 1
	candidate.Revision++
	if err := m.Store.Save(candidate); err != nil {
		return gatewayprotocol.VPNPeerConfig{}, err
	}
	if err := m.Link.Configure(vpn.InterfaceName, wireguard.Config{Peers: []wireguard.Peer{kernelPeer(peer)}}); err != nil {
		if saveErr := m.Store.Save(state); saveErr != nil {
			return gatewayprotocol.VPNPeerConfig{}, errors.Join(err, fmt.Errorf("undo the new VPN device: %w", saveErr))
		}
		return gatewayprotocol.VPNPeerConfig{}, fmt.Errorf("the VPN interface did not accept the device: %w", err)
	}
	m.publish(candidate)
	m.changed()
	m.log("VPN device added", "peer_id", peer.ID, "address", peer.IPv4)
	return gatewayprotocol.VPNPeerConfig{Peer: peerStatus(peer), Config: config.Render(), FileName: vpn.FileName(name)}, nil
}

// SetPeerDevice records the inventory device a peer was named as.
func (m *VPNManager) SetPeerDevice(params gatewayprotocol.SetVPNPeerDeviceParams) (gatewayprotocol.VPNPeerStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.Store.Load()
	if err != nil {
		return gatewayprotocol.VPNPeerStatus{}, err
	}
	peer, index, ok := state.PeerByID(params.PeerID)
	if !ok {
		return gatewayprotocol.VPNPeerStatus{}, errors.New("no such VPN device")
	}
	if peer.DeviceID == params.DeviceID {
		return peerStatus(peer), nil
	}
	candidate := state
	candidate.Peers = append([]vpn.Peer(nil), state.Peers...)
	candidate.Peers[index].DeviceID = params.DeviceID
	candidate.Revision++
	if err := m.Store.Save(candidate); err != nil {
		return gatewayprotocol.VPNPeerStatus{}, err
	}
	m.publish(candidate)
	m.changed()
	return peerStatus(candidate.Peers[index]), nil
}

// RevokePeer removes a device. The revocation is saved first, so a peer
// can never come back; the interface drops it at once (or, should that
// fail, on the next reconcile, and the error says so).
func (m *VPNManager) RevokePeer(ctx context.Context, params gatewayprotocol.RevokeVPNPeerParams) (gatewayprotocol.VPNPeerStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.Store.Load()
	if err != nil {
		return gatewayprotocol.VPNPeerStatus{}, err
	}
	peer, index, ok := state.PeerByID(params.PeerID)
	if !ok {
		return gatewayprotocol.VPNPeerStatus{}, errors.New("no such VPN device")
	}
	candidate := state
	candidate.Peers = append(append([]vpn.Peer(nil), state.Peers[:index]...), state.Peers[index+1:]...)
	candidate.Revision++
	if err := m.Store.Save(candidate); err != nil {
		return gatewayprotocol.VPNPeerStatus{}, err
	}
	m.publish(candidate)
	m.changed()
	m.log("VPN device revoked", "peer_id", peer.ID, "address", peer.IPv4)
	if state.Settings.Enabled {
		if err := m.Link.Configure(vpn.InterfaceName, wireguard.Config{Peers: []wireguard.Peer{{PublicKey: peer.PublicKey, Remove: true}}}); err != nil && !errors.Is(err, wireguard.ErrNotFound) {
			return peerStatus(peer), fmt.Errorf("the device is revoked, but the VPN interface still has it (retrying every 15 s): %w", err)
		}
	}
	return peerStatus(peer), nil
}

func kernelPeer(peer vpn.Peer) wireguard.Peer {
	result := wireguard.Peer{PublicKey: peer.PublicKey}
	for _, text := range []string{peer.IPv4, peer.IPv6} {
		if address, err := netip.ParseAddr(text); err == nil {
			result.AllowedIPs = append(result.AllowedIPs, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	return result
}

// applyLocked makes the kernel match state: interface, key, port, peers,
// addresses, forwarding and firewall. It is idempotent and keeps running
// sessions.
func (m *VPNManager) applyLocked(ctx context.Context, state vpn.State) error {
	err := m.applyInterface(state)
	if err == nil {
		err = m.applyFirewallLocked(ctx, state)
	}
	if err != nil {
		message := err.Error()
		m.problem.Store(&message)
		if m.segment.Swap(nil) != nil {
			m.changed()
		}
		return err
	}
	m.problem.Store(nil)
	previous := m.segment.Load()
	m.publish(state)
	if current := m.segment.Load(); previous == nil || current == nil || previous.ipv6Routed != current.ipv6Routed || previous.state.Revision != current.state.Revision {
		m.changed()
	}
	return nil
}

// publish exposes the running state; a change in what the rest of gatewayd
// sees is announced through Changed by the caller.
func (m *VPNManager) publish(state vpn.State) {
	if !state.Settings.Enabled {
		m.segment.Store(nil)
		return
	}
	m.segment.Store(&vpnRuntime{state: state, ipv6Routed: m.ipv6Routed()})
}

func (m *VPNManager) applyInterface(state vpn.State) error {
	name := vpn.InterfaceName
	link, err := m.Link.GetLink(name)
	switch {
	case errors.Is(err, wireguard.ErrNotFound):
		if err := m.Link.CreateLink(name, vpn.MTU); err != nil {
			if errors.Is(err, wireguard.ErrUnsupported) {
				return errors.New("this kernel has no WireGuard support; install the kernel's extra modules (linux-modules-extra) or use a standard Ubuntu kernel")
			}
			return err
		}
	case err != nil:
		return err
	case link.Kind != "wireguard":
		return fmt.Errorf("an interface named %s already exists and is not ShakerProxy's WireGuard interface; remove or rename it", name)
	}
	device, err := m.Link.GetDevice(name)
	if err != nil {
		return err
	}
	config := wireguard.Config{}
	if device.PrivateKey != state.PrivateKey || device.ListenPort != state.Settings.ListenPort {
		key := [32]byte(state.PrivateKey)
		config.PrivateKey, config.ListenPort = &key, state.Settings.ListenPort
	}
	desired := map[vpn.Key]wireguard.Peer{}
	for _, peer := range state.Peers {
		desired[peer.PublicKey] = kernelPeer(peer)
	}
	for _, live := range device.Peers {
		want, ok := desired[vpn.Key(live.PublicKey)]
		if !ok {
			config.Peers = append(config.Peers, wireguard.Peer{PublicKey: live.PublicKey, Remove: true})
			continue
		}
		if samePrefixes(live.AllowedIPs, want.AllowedIPs) {
			delete(desired, vpn.Key(live.PublicKey))
		}
	}
	for _, peer := range state.Peers {
		if want, ok := desired[peer.PublicKey]; ok {
			config.Peers = append(config.Peers, want)
		}
	}
	if config.PrivateKey != nil || len(config.Peers) != 0 {
		if err := m.Link.Configure(name, config); err != nil {
			if errors.Is(err, syscall.EADDRINUSE) {
				return fmt.Errorf("UDP port %d is already in use on this host; choose another VPN port", state.Settings.ListenPort)
			}
			return err
		}
	}
	wanted := []netip.Prefix{
		netip.PrefixFrom(state.GatewayIPv4(), state.IPv4Prefix().Bits()),
		netip.PrefixFrom(state.GatewayIPv6(), state.IPv6PrefixValue().Bits()),
	}
	if !m.ipv6Available() {
		wanted = wanted[:1]
	}
	present, err := m.Link.Addresses(name)
	if err != nil {
		return err
	}
	for _, prefix := range present {
		if prefix.Addr().Is6() && prefix.Addr().IsLinkLocalUnicast() {
			continue
		}
		if !containsPrefix(wanted, prefix) {
			if err := m.Link.DeleteAddress(name, prefix); err != nil {
				return err
			}
		}
	}
	for _, prefix := range wanted {
		if !containsPrefix(present, prefix) {
			if err := m.Link.AddAddress(name, prefix); err != nil {
				return err
			}
		}
	}
	if link, err := m.Link.GetLink(name); err != nil || !link.Up {
		if err := m.Link.SetLinkUp(name); err != nil {
			return err
		}
	}
	// VPN devices are routed. Docker already enables IPv4 forwarding on a
	// ShakerProxy host; a VPN-only install may not have it yet.
	if value, err := m.Link.ReadSysctl("/proc/sys/net/ipv4/ip_forward"); err != nil || value != "1" {
		if err := m.Link.WriteSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
			return fmt.Errorf("enable IPv4 forwarding: %w", err)
		}
	}
	return nil
}

func samePrefixes(left, right []netip.Prefix) bool {
	if len(left) != len(right) {
		return false
	}
	for _, prefix := range right {
		if !containsPrefix(left, prefix) {
			return false
		}
	}
	return true
}

func containsPrefix(list []netip.Prefix, want netip.Prefix) bool {
	for _, prefix := range list {
		if prefix == want {
			return true
		}
	}
	return false
}

// ipv6Routed reports whether this host forwards IPv6. ShakerProxy never
// turns IPv6 forwarding on for the VPN alone: on a host that learns its
// own IPv6 route from router advertisements that would cut it off. Without
// it, VPN devices' IPv6 ends at ShakerProxy and they use IPv4.
func (m *VPNManager) ipv6Routed() bool {
	if !m.ipv6Available() {
		return false
	}
	value, err := m.Link.ReadSysctl("/proc/sys/net/ipv6/conf/all/forwarding")
	return err == nil && value == "1"
}

func (m *VPNManager) ipv6Available() bool {
	return m.IPv6Available != nil && m.IPv6Available()
}

// teardownLocked removes the interface and the firewall chains.
func (m *VPNManager) teardownLocked(ctx context.Context) error {
	firewallErr := m.removeFirewallLocked(ctx)
	var linkErr error
	link, err := m.Link.GetLink(vpn.InterfaceName)
	switch {
	case errors.Is(err, wireguard.ErrNotFound), errors.Is(err, wireguard.ErrUnsupported):
	case err != nil:
		linkErr = err
	case link.Kind == "wireguard":
		linkErr = m.Link.DeleteLink(vpn.InterfaceName)
	}
	m.problem.Store(nil)
	if m.segment.Swap(nil) != nil {
		m.changed()
	}
	return errors.Join(firewallErr, linkErr)
}

func (m *VPNManager) changed() {
	if m.Changed != nil {
		m.Changed()
	}
}

// defaultHost is the address devices connect to unless the administrator
// sets one: the address this host reaches the internet from (in a
// single-arm lab, its lab address), else the confirmed lab's gateway.
func (m *VPNManager) defaultHost() string {
	if m.OutboundAddress != nil {
		if address := m.OutboundAddress(); address != "" {
			return address
		}
	}
	if _, plan, ok := confirmedLabPlan(m.NetworkState); ok {
		return labGatewayIPv4(plan)
	}
	return ""
}

// outboundIPv4 asks the kernel which source address reaches the internet.
// Connecting a UDP socket sends nothing.
func outboundIPv4() string {
	connection, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return ""
	}
	defer connection.Close()
	address, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok || address.IP.IsLoopback() || address.IP.IsUnspecified() {
		return ""
	}
	return address.IP.String()
}

func (m *VPNManager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *VPNManager) log(message string, attributes ...any) {
	if m.Logger != nil {
		m.Logger.Info(message, attributes...)
	}
}

// warn logs each distinct reconcile failure once.
func (m *VPNManager) warn(message string, err error) {
	if err.Error() == m.lastWarn {
		return
	}
	m.lastWarn = err.Error()
	if m.Logger != nil {
		m.Logger.Warn(message, "error", err)
	}
}

// coordinate takes the cross-process lock the traffic policy uses for the
// same parent chains.
func (m *VPNManager) coordinate(ctx context.Context) (*policycoordination.Lock, error) {
	return policycoordination.Acquire(ctx, m.CoordinationLockPath)
}
