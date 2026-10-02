// Package vpn is ShakerProxy's WireGuard lab: a phone or laptop anywhere
// scans a QR code with the WireGuard app and from then on sends all of its
// traffic (IPv4, IPv6 and local-network destinations) through ShakerProxy.
// This package holds the pure parts: settings, peers, keys, the device
// configuration and the firewall rules. gatewayd applies them.
package vpn

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion = 1
	// InterfaceName is the kernel WireGuard interface gatewayd owns.
	InterfaceName     = "wg-lab"
	DefaultListenPort = 51820
	DefaultIPv4CIDR   = "10.89.0.0/24"
	// MTU is WireGuard's default: 1500 less the IPv6, UDP and WireGuard
	// headers, so the tunnel works over IPv4 and IPv6 paths alike.
	MTU = 1420
	// PersistentKeepalive keeps the device's home-router NAT mapping open so
	// pushes and other inbound replies reach an idle phone.
	PersistentKeepalive = 25
	MaxPeers            = 250
	MaxNameLength       = 64
)

// Settings is what an administrator chooses. Everything else (keys, the
// IPv6 prefix, peers) is generated.
type Settings struct {
	Enabled    bool `json:"enabled"`
	ListenPort int  `json:"listen_port"`
	// Endpoint is the host (and optional port) devices connect to, as it
	// appears in their configuration. Empty means ShakerProxy's lab-side
	// address and ListenPort. Set it to a public name or address, with the
	// router's forwarded port, to use the VPN from outside the network.
	Endpoint string `json:"endpoint,omitempty"`
	IPv4CIDR string `json:"ipv4_cidr"`
	// AllowPeerToPeer lets VPN devices reach each other. Off by default:
	// each VPN device only reaches the internet and the networks behind
	// ShakerProxy.
	AllowPeerToPeer bool `json:"allow_peer_to_peer"`
}

// DefaultSettings is VPN mode off, ready to turn on.
func DefaultSettings() Settings {
	return Settings{ListenPort: DefaultListenPort, IPv4CIDR: DefaultIPv4CIDR}
}

// Peer is one device allowed on the VPN. Its private key is shown once, in
// the configuration handed to the device, and never stored.
type Peer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	DeviceID  string    `json:"device_id,omitempty"`
	PublicKey Key       `json:"public_key"`
	IPv4      string    `json:"ipv4"`
	IPv6      string    `json:"ipv6"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// State is gatewayd's root-only VPN record.
type State struct {
	Schema   int      `json:"schema"`
	Revision uint64   `json:"revision"`
	Settings Settings `json:"settings"`
	// PrivateKey is the server key, generated once.
	PrivateKey Key `json:"private_key"`
	// IPv6Prefix is a random unique-local /64 (RFC 4193), generated once.
	IPv6Prefix string `json:"ipv6_prefix"`
	Peers      []Peer `json:"peers"`
	// NextHost is where address allocation continues, so a revoked device's
	// address (still naming it in Devices and in recorded traffic) is not
	// handed to a new device until the whole network has been used.
	NextHost uint32 `json:"next_host,omitempty"`
}

var (
	peerIDPattern   = regexp.MustCompile(`^vpn-[a-f0-9]{16}$`)
	deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	hostnamePattern = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)
)

// NewState generates the server key and IPv6 prefix with VPN mode off.
func NewState() (State, error) {
	key, err := NewPrivateKey()
	if err != nil {
		return State{}, err
	}
	prefix, err := newULAPrefix()
	if err != nil {
		return State{}, err
	}
	return State{Schema: SchemaVersion, Settings: DefaultSettings(), PrivateKey: key, IPv6Prefix: prefix.String(), Peers: []Peer{}}, nil
}

// newULAPrefix returns fdXX:XXXX:XXXX:1::/64 with a random 40-bit global ID.
func newULAPrefix() (netip.Prefix, error) {
	var bytes [16]byte
	bytes[0] = 0xfd
	if _, err := rand.Read(bytes[1:6]); err != nil {
		return netip.Prefix{}, errors.New("generate the VPN IPv6 prefix")
	}
	bytes[7] = 1
	return netip.PrefixFrom(netip.AddrFrom16(bytes), 64), nil
}

// NewPeerID returns a random peer identifier.
func NewPeerID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("generate a VPN peer ID")
	}
	return "vpn-" + hex.EncodeToString(raw[:]), nil
}

// ValidPeerID reports a well-formed peer identifier.
func ValidPeerID(id string) bool { return peerIDPattern.MatchString(id) }

// Normalize fills defaults and rejects settings gatewayd cannot apply.
func (s Settings) Normalize() (Settings, error) {
	if s.ListenPort == 0 {
		s.ListenPort = DefaultListenPort
	}
	if s.ListenPort < 1 || s.ListenPort > 65535 {
		return Settings{}, errors.New("the VPN port must be between 1 and 65535")
	}
	switch s.ListenPort {
	case 53, 67, 68, 123, 547, 1053, 5353:
		return Settings{}, fmt.Errorf("UDP port %d is used by DNS, DHCP or time service; choose another VPN port such as %d", s.ListenPort, DefaultListenPort)
	}
	s.Endpoint = strings.TrimSpace(s.Endpoint)
	if s.Endpoint != "" {
		if _, _, err := SplitEndpoint(s.Endpoint); err != nil {
			return Settings{}, err
		}
	}
	if strings.TrimSpace(s.IPv4CIDR) == "" {
		s.IPv4CIDR = DefaultIPv4CIDR
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(s.IPv4CIDR))
	if err != nil || !prefix.Addr().Is4() {
		return Settings{}, errors.New("the VPN network must be an IPv4 CIDR such as 10.89.0.0/24")
	}
	if prefix.Bits() < 16 || prefix.Bits() > 29 {
		return Settings{}, errors.New("the VPN network must be between a /16 and a /29")
	}
	prefix = prefix.Masked()
	if !prefix.Addr().IsPrivate() && !sharedAddressSpace.Contains(prefix.Addr()) {
		return Settings{}, errors.New("the VPN network must be a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10)")
	}
	s.IPv4CIDR = prefix.String()
	return s, nil
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// SplitEndpoint parses "host", "host:port" or "[v6]:port". The port is 0
// when absent.
func SplitEndpoint(endpoint string) (string, int, error) {
	invalid := errors.New("the VPN address must be a host name or IP address, optionally with :port")
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || len(endpoint) > 260 || strings.ContainsAny(endpoint, " \t\r\n/\\@") {
		return "", 0, invalid
	}
	bare := endpoint
	if strings.HasPrefix(bare, "[") && strings.HasSuffix(bare, "]") {
		bare = bare[1 : len(bare)-1]
	}
	if address, err := netip.ParseAddr(bare); err == nil {
		if address.Zone() != "" {
			return "", 0, invalid
		}
		return address.String(), 0, nil
	}
	host, port := endpoint, 0
	if index := strings.LastIndex(endpoint, ":"); index >= 0 {
		host = endpoint[:index]
		value, err := strconv.Atoi(endpoint[index+1:])
		if err != nil || value < 1 || value > 65535 {
			return "", 0, invalid
		}
		port = value
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
			address, err := netip.ParseAddr(host)
			if err != nil || !address.Is6() || address.Zone() != "" {
				return "", 0, invalid
			}
			return address.String(), port, nil
		}
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.Is4() {
			return "", 0, invalid // an IPv6 address with a port needs brackets
		}
		return address.String(), port, nil
	}
	if len(host) > 253 || !hostnamePattern.MatchString(host) {
		return "", 0, invalid
	}
	return strings.ToLower(strings.TrimSuffix(host, ".")), port, nil
}

// JoinEndpoint formats host and port as a WireGuard endpoint.
func JoinEndpoint(host string, port int) string {
	if address, err := netip.ParseAddr(host); err == nil && address.Is6() {
		return "[" + address.String() + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// EffectiveEndpoint is the endpoint written into device configurations:
// the administrator's choice, or defaultHost with the listen port.
func (s Settings) EffectiveEndpoint(defaultHost string) (string, error) {
	host, port := defaultHost, 0
	if s.Endpoint != "" {
		parsed, parsedPort, err := SplitEndpoint(s.Endpoint)
		if err != nil {
			return "", err
		}
		host, port = parsed, parsedPort
	}
	if host == "" {
		return "", errors.New("ShakerProxy has no address devices can reach yet; set the VPN address to this host's name or IP")
	}
	if port == 0 {
		port = s.ListenPort
	}
	return JoinEndpoint(host, port), nil
}

// ValidateName checks a peer name (shown in the device list and Traffic).
func ValidateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > MaxNameLength || !utf8.ValidString(name) {
		return "", fmt.Errorf("give the device a name of 1-%d characters", MaxNameLength)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("the device name must be one line of text")
		}
	}
	return name, nil
}

// IPv4Prefix is the VPN's IPv4 network.
func (s State) IPv4Prefix() netip.Prefix {
	prefix, err := netip.ParsePrefix(s.Settings.IPv4CIDR)
	if err != nil {
		return netip.Prefix{}
	}
	return prefix.Masked()
}

// IPv6PrefixValue is the VPN's unique-local IPv6 network.
func (s State) IPv6PrefixValue() netip.Prefix {
	prefix, err := netip.ParsePrefix(s.IPv6Prefix)
	if err != nil {
		return netip.Prefix{}
	}
	return prefix.Masked()
}

// GatewayIPv4 and GatewayIPv6 are ShakerProxy's own addresses on the VPN:
// the first host of each network. Devices use the IPv4 one for DNS.
func (s State) GatewayIPv4() netip.Addr { return hostAt(s.IPv4Prefix(), 1) }
func (s State) GatewayIPv6() netip.Addr { return hostAt(s.IPv6PrefixValue(), 1) }

// hostAt returns the address at offset from the network address.
func hostAt(prefix netip.Prefix, offset uint32) netip.Addr {
	if !prefix.IsValid() {
		return netip.Addr{}
	}
	bytes := prefix.Masked().Addr().AsSlice()
	carry := offset
	for index := len(bytes) - 1; index >= 0 && carry > 0; index-- {
		sum := uint32(bytes[index]) + carry&0xff
		bytes[index] = byte(sum)
		carry = carry>>8 + sum>>8
	}
	address, _ := netip.AddrFromSlice(bytes)
	if !prefix.Contains(address) {
		return netip.Addr{}
	}
	return address
}

// NextAddresses returns the next free IPv4 and IPv6 addresses and their
// host offset (pass it to TakeHost). Offsets start at 2 (1 is ShakerProxy)
// and only wrap around, reusing revoked devices' addresses, at the end of
// the network.
func (s State) NextAddresses() (netip.Addr, netip.Addr, uint32, error) {
	if len(s.Peers) >= MaxPeers {
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("the VPN already has %d devices; revoke one first", MaxPeers)
	}
	prefix4, prefix6 := s.IPv4Prefix(), s.IPv6PrefixValue()
	if !prefix4.IsValid() || !prefix6.IsValid() {
		return netip.Addr{}, netip.Addr{}, 0, errors.New("the VPN networks are not configured")
	}
	used := map[netip.Addr]bool{}
	for _, peer := range s.Peers {
		if address, err := netip.ParseAddr(peer.IPv4); err == nil {
			used[address] = true
		}
	}
	last := uint32(1)<<(32-prefix4.Bits()) - 2 // without network and broadcast
	start := s.NextHost
	if start < 2 || start > last {
		start = 2
	}
	for step := uint32(0); step <= last-2; step++ {
		offset := 2 + (start-2+step)%(last-1)
		address := hostAt(prefix4, offset)
		if !address.IsValid() || used[address] {
			continue
		}
		return address, hostAt(prefix6, offset), offset, nil
	}
	return netip.Addr{}, netip.Addr{}, 0, errors.New("the VPN network has no free address; use a larger network or revoke a device")
}

// PeerByID returns a peer and its index.
func (s State) PeerByID(id string) (Peer, int, bool) {
	for index, peer := range s.Peers {
		if peer.ID == id {
			return peer, index, true
		}
	}
	return Peer{}, 0, false
}

// Validate checks a loaded or about-to-be-saved state.
func (s State) Validate() error {
	if s.Schema != SchemaVersion {
		return errors.New("unsupported VPN state schema")
	}
	if s.PrivateKey.IsZero() {
		return errors.New("the VPN state has no server key")
	}
	if _, err := s.Settings.Normalize(); err != nil {
		return err
	}
	prefix6 := s.IPv6PrefixValue()
	if !prefix6.IsValid() || prefix6.Bits() != 64 || !prefix6.Addr().Is6() || !ulaPrefix.Contains(prefix6.Addr()) {
		return errors.New("the VPN IPv6 prefix must be a unique-local /64")
	}
	if len(s.Peers) > MaxPeers {
		return errors.New("the VPN has too many devices")
	}
	prefix4 := s.IPv4Prefix()
	ids, keys, addresses := map[string]bool{}, map[Key]bool{}, map[string]bool{}
	for _, peer := range s.Peers {
		if !ValidPeerID(peer.ID) || ids[peer.ID] {
			return errors.New("a VPN device has an invalid or duplicate ID")
		}
		if _, err := ValidateName(peer.Name); err != nil {
			return err
		}
		if peer.DeviceID != "" && !deviceIDPattern.MatchString(peer.DeviceID) {
			return errors.New("a VPN device has an invalid inventory device ID")
		}
		if peer.PublicKey.IsZero() || keys[peer.PublicKey] || peer.PublicKey == s.PrivateKey.PublicKey() {
			return errors.New("a VPN device has a missing or duplicate key")
		}
		address4, err4 := netip.ParseAddr(peer.IPv4)
		address6, err6 := netip.ParseAddr(peer.IPv6)
		if err4 != nil || !address4.Is4() || !prefix4.Contains(address4) || address4 == s.GatewayIPv4() || address4 == lastAddress(prefix4) || address4 == prefix4.Addr() {
			return fmt.Errorf("VPN device %q has an address outside the VPN network", peer.Name)
		}
		if err6 != nil || !address6.Is6() || !prefix6.Contains(address6) || address6 == s.GatewayIPv6() {
			return fmt.Errorf("VPN device %q has an IPv6 address outside the VPN network", peer.Name)
		}
		if addresses[peer.IPv4] || addresses[peer.IPv6] {
			return errors.New("two VPN devices share an address")
		}
		ids[peer.ID], keys[peer.PublicKey], addresses[peer.IPv4], addresses[peer.IPv6] = true, true, true, true
	}
	return nil
}

var ulaPrefix = netip.MustParsePrefix("fd00::/8")

func lastAddress(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().As4()
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	value |= uint32(1)<<(32-prefix.Bits()) - 1
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// SortedPeers returns the peers by address.
func (s State) SortedPeers() []Peer {
	peers := append([]Peer(nil), s.Peers...)
	sort.Slice(peers, func(i, j int) bool {
		left, _ := netip.ParseAddr(peers[i].IPv4)
		right, _ := netip.ParseAddr(peers[j].IPv4)
		return left.Less(right)
	})
	return peers
}
