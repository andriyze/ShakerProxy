package vpn

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RFC 7748 section 6.1: Alice's key pair.
const (
	alicePrivate = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
	alicePublic  = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
)

func TestPublicKeyMatchesRFC7748(t *testing.T) {
	private, err := ParseKey(alicePrivate)
	if err != nil {
		t.Fatal(err)
	}
	if got := private.PublicKey().String(); got != alicePublic {
		t.Fatalf("public key = %s, want %s", got, alicePublic)
	}
	generated, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if generated[0]&7 != 0 || generated[31]&128 != 0 || generated[31]&64 == 0 {
		t.Fatalf("generated key is not clamped: %x", generated)
	}
	if _, err := ParseKey("not base64"); err == nil {
		t.Fatal("an invalid key parsed")
	}
	encoded, _ := json.Marshal(struct{ K Key }{generated})
	var decoded struct{ K Key }
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.K != generated {
		t.Fatalf("key JSON round trip: %s %v", encoded, err)
	}
}

func TestSettingsDefaultsAndLimits(t *testing.T) {
	settings, err := Settings{Enabled: true}.Normalize()
	if err != nil || settings.ListenPort != DefaultListenPort || settings.IPv4CIDR != DefaultIPv4CIDR {
		t.Fatalf("defaults = %+v, %v", settings, err)
	}
	if settings, err := (Settings{IPv4CIDR: "10.89.3.7/24"}).Normalize(); err != nil || settings.IPv4CIDR != "10.89.3.0/24" {
		t.Fatalf("CIDR is not masked: %+v %v", settings, err)
	}
	for _, bad := range []Settings{
		{ListenPort: 70000},
		{ListenPort: 53},
		{IPv4CIDR: "8.8.8.0/24"},
		{IPv4CIDR: "10.0.0.0/8"},
		{IPv4CIDR: "10.89.0.0/30"},
		{IPv4CIDR: "fd00::/64"},
		{Endpoint: "http://example.com"},
		{Endpoint: "fd00::1:51820"},
	} {
		if _, err := bad.Normalize(); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

func TestEndpoints(t *testing.T) {
	for _, check := range []struct {
		in   string
		host string
		port int
	}{
		{"192.168.10.177", "192.168.10.177", 0},
		{"203.0.113.9:443", "203.0.113.9", 443},
		{"Home.Example.NET.", "home.example.net", 0},
		{"vpn.example.net:51821", "vpn.example.net", 51821},
		{"2001:db8::1", "2001:db8::1", 0},
		{"[2001:db8::1]", "2001:db8::1", 0},
		{"[2001:db8::1]:51820", "2001:db8::1", 51820},
	} {
		host, port, err := SplitEndpoint(check.in)
		if err != nil || host != check.host || port != check.port {
			t.Errorf("SplitEndpoint(%q) = %q %d %v", check.in, host, port, err)
		}
	}
	settings := Settings{ListenPort: 51820}
	if endpoint, _ := settings.EffectiveEndpoint("192.168.10.177"); endpoint != "192.168.10.177:51820" {
		t.Fatalf("default endpoint = %s", endpoint)
	}
	settings.Endpoint = "home.example.net:443"
	if endpoint, _ := settings.EffectiveEndpoint("192.168.10.177"); endpoint != "home.example.net:443" {
		t.Fatalf("set endpoint = %s", endpoint)
	}
	settings.Endpoint = "2001:db8::7"
	if endpoint, _ := settings.EffectiveEndpoint(""); endpoint != "[2001:db8::7]:51820" {
		t.Fatalf("IPv6 endpoint = %s", endpoint)
	}
	if _, err := (Settings{ListenPort: 51820}).EffectiveEndpoint(""); err == nil {
		t.Fatal("an endpoint without any host was produced")
	}
}

func testState(t *testing.T) State {
	t.Helper()
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	state.Settings.Enabled = true
	state.IPv6Prefix = "fd12:3456:789a:1::/64"
	return state
}

func addPeer(t *testing.T, state *State, name string) (Peer, Key) {
	t.Helper()
	address4, address6, offset, err := state.NextAddresses()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewPrivateKey()
	id, _ := NewPeerID()
	peer := Peer{ID: id, Name: name, PublicKey: key.PublicKey(), IPv4: address4.String(), IPv6: address6.String(), CreatedAt: time.Now().UTC()}
	state.Peers = append(state.Peers, peer)
	state.NextHost = offset + 1
	return peer, key
}

func TestNewStateIsOffWithAUniqueLocalPrefix(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	prefix := state.IPv6PrefixValue()
	if state.Settings.Enabled || prefix.Bits() != 64 || prefix.Addr().As16()[0] != 0xfd || state.PrivateKey.IsZero() {
		t.Fatalf("new state = %+v", state)
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	if state.GatewayIPv4().String() != "10.89.0.1" || !prefix.Contains(state.GatewayIPv6()) {
		t.Fatalf("gateways %s %s", state.GatewayIPv4(), state.GatewayIPv6())
	}
}

func TestAddressesAreNotReusedUntilTheNetworkWraps(t *testing.T) {
	state := testState(t)
	state.Settings.IPv4CIDR = "10.89.0.0/29" // hosts .2-.6
	pixel, _ := addPeer(t, &state, "Pixel")
	laptop, _ := addPeer(t, &state, "Laptop")
	if pixel.IPv4 != "10.89.0.2" || laptop.IPv4 != "10.89.0.3" || pixel.IPv6 != "fd12:3456:789a:1::2" {
		t.Fatalf("first addresses %s %s %s", pixel.IPv4, laptop.IPv4, pixel.IPv6)
	}
	// Revoking Pixel does not hand .2 to the next device.
	state.Peers = state.Peers[1:]
	third, _ := addPeer(t, &state, "Tablet")
	if third.IPv4 != "10.89.0.4" {
		t.Fatalf("a revoked address was reused early: %s", third.IPv4)
	}
	addPeer(t, &state, "Four")
	addPeer(t, &state, "Five")
	// .2 is the only free address left: the network wrapped.
	wrapped, _ := addPeer(t, &state, "Six")
	if wrapped.IPv4 != "10.89.0.2" {
		t.Fatalf("after wrapping got %s", wrapped.IPv4)
	}
	if _, _, _, err := state.NextAddresses(); err == nil || !strings.Contains(err.Error(), "no free address") {
		t.Fatalf("a full network gave %v", err)
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	state.Peers[1].IPv4 = state.Peers[0].IPv4
	if err := state.Validate(); err == nil {
		t.Fatal("two devices with one address validated")
	}
}

func TestDeviceConfigIsAFullTunnelWithShakerProxyDNS(t *testing.T) {
	state := testState(t)
	peer, key := addPeer(t, &state, "Pixel 9")
	config, err := DeviceConfig(state, peer, key, "192.168.10.177:51820")
	if err != nil {
		t.Fatal(err)
	}
	text := config.Render()
	for _, want := range []string{
		"[Interface]\nPrivateKey = " + key.String() + "\n",
		"Address = 10.89.0.2/32, fd12:3456:789a:1::2/128\n",
		"DNS = 10.89.0.1\n",
		"[Peer]\nPublicKey = " + state.PrivateKey.PublicKey().String() + "\n",
		"AllowedIPs = 0.0.0.0/0, ::/0\n",
		"Endpoint = 192.168.10.177:51820\n",
		"PersistentKeepalive = 25\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("config lacks %q:\n%s", want, text)
		}
	}
	// The QR payload is the configuration itself; it must stay scannable.
	if len(text) > 331 {
		t.Fatalf("configuration is %d bytes; QR version 13-M holds 331", len(text))
	}
	parsed, err := ParseClientConfig(text)
	if err != nil || parsed.PrivateKey != key || parsed.ServerPublicKey != state.PrivateKey.PublicKey() || parsed.Endpoint != "192.168.10.177:51820" || len(parsed.Addresses) != 2 || parsed.Keepalive != 25 {
		t.Fatalf("round trip = %+v, %v", parsed, err)
	}
	if _, err := DeviceConfig(state, peer, Key{1}, "192.168.10.177:51820"); err == nil {
		t.Fatal("a configuration with another device's key was rendered")
	}
	if FileName("Pixel 9 (VPN) — Andriy's") != "pixel-9-vpn-and.conf" || FileName("!!!") != "shakerproxy.conf" {
		t.Fatalf("file names %q %q", FileName("Pixel 9 (VPN) — Andriy's"), FileName("!!!"))
	}
}

func TestFirewallKeepsDevicesOffShakerProxyAndEachOther(t *testing.T) {
	state := testState(t)
	rules, err := RenderFirewall(state, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"-A SHAKERPROXY-VPN-INPUT -p udp --dport 51820 -j ACCEPT",
		"-A SHAKERPROXY-VPN-INPUT -i wg-lab -m conntrack --ctstate DNAT -j RETURN",
		"-A SHAKERPROXY-VPN-INPUT -i wg-lab -j DROP",
		"-A SHAKERPROXY-VPN-FORWARD -i wg-lab ! -s 10.89.0.0/24 -j DROP",
		"-A SHAKERPROXY-VPN-FORWARD -i wg-lab -m conntrack --ctstate DNAT -j DROP",
		"-A SHAKERPROXY-VPN-FORWARD -i wg-lab -o wg-lab -j DROP",
		"-A SHAKERPROXY-VPN-FORWARD -i wg-lab -j ACCEPT",
		"-A SHAKERPROXY-VPN-FORWARD -o wg-lab -j DROP",
	} {
		if !strings.Contains(rules.Filter, want+"\n") {
			t.Fatalf("filter lacks %q:\n%s", want, rules.Filter)
		}
	}
	// Order matters: the DNAT drop (management UI) and peer isolation come
	// before the accept.
	if strings.Index(rules.Filter, "--ctstate DNAT -j DROP") > strings.Index(rules.Filter, "-i wg-lab -j ACCEPT") || strings.Index(rules.Filter, "FORWARD -o wg-lab -j DROP\n") < strings.Index(rules.Filter, "FORWARD -o wg-lab -m conntrack") {
		t.Fatalf("filter order is wrong:\n%s", rules.Filter)
	}
	if !strings.Contains(rules.NAT, "-A SHAKERPROXY-VPN-POSTROUTING -s 10.89.0.0/24 ! -o wg-lab -j MASQUERADE\n") || !strings.HasPrefix(rules.NAT, "*nat\n") {
		t.Fatalf("nat = %s", rules.NAT)
	}
	state.Settings.AllowPeerToPeer = true
	state.Settings.ListenPort = 443
	rules6, err := RenderFirewall(state, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules6.Filter, "-i wg-lab -o wg-lab -j ACCEPT\n") || !strings.Contains(rules6.Filter, "--dport 443 -j ACCEPT") || !strings.Contains(rules6.Filter, "! -s fd12:3456:789a:1::/64 -j DROP") || !strings.Contains(rules6.Filter, "--icmpv6-type echo-request") {
		t.Fatalf("IPv6 filter:\n%s", rules6.Filter)
	}
	if !strings.Contains(rules6.NAT, "-s fd12:3456:789a:1::/64 ! -o wg-lab -j MASQUERADE") {
		t.Fatalf("IPv6 nat = %s", rules6.NAT)
	}
	empty := EmptyFirewall()
	if strings.Count(empty.Filter, "-j RETURN") != 2 || strings.Contains(empty.Filter, "ACCEPT") {
		t.Fatalf("empty firewall = %s", empty.Filter)
	}
}

func TestStoreKeepsTheServerKeyRootOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpn.json")
	store := Store{Path: path}
	first, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, %v", info.Mode(), err)
	}
	second, err := store.Load()
	if err != nil || second.PrivateKey != first.PrivateKey || second.IPv6Prefix != first.IPv6Prefix {
		t.Fatal("the server key changed between loads")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "root only") {
		t.Fatalf("a world-readable state loaded: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	bad := first
	bad.Peers = []Peer{{ID: "vpn-zz", Name: "x"}}
	if err := store.Save(bad); err == nil {
		t.Fatal("an invalid state was saved")
	}
	if _, err := netip.ParsePrefix(first.IPv6Prefix); err != nil {
		t.Fatal(err)
	}
}
