package vpn

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// FullTunnel is what every device sends through ShakerProxy: all IPv4 and
// all IPv6, local networks included, so nothing reaches another router.
var FullTunnel = []string{"0.0.0.0/0", "::/0"}

// ClientConfig is a device's WireGuard configuration in the wg-quick format
// the WireGuard apps import from a file or a QR code.
type ClientConfig struct {
	PrivateKey      Key
	Addresses       []netip.Prefix
	DNS             []netip.Addr
	ServerPublicKey Key
	Endpoint        string
	AllowedIPs      []string
	Keepalive       int
}

// DeviceConfig builds a full-tunnel configuration for peer. DNS points at
// ShakerProxy's VPN address, so every lookup reaches its DNS forwarder.
func DeviceConfig(state State, peer Peer, privateKey Key, endpoint string) (ClientConfig, error) {
	address4, err4 := netip.ParseAddr(peer.IPv4)
	address6, err6 := netip.ParseAddr(peer.IPv6)
	if err4 != nil || err6 != nil {
		return ClientConfig{}, errors.New("the VPN device has no address")
	}
	if privateKey.PublicKey() != peer.PublicKey {
		return ClientConfig{}, errors.New("the device key does not match the VPN device")
	}
	if _, _, err := SplitEndpoint(endpoint); err != nil {
		return ClientConfig{}, err
	}
	return ClientConfig{
		PrivateKey:      privateKey,
		Addresses:       []netip.Prefix{netip.PrefixFrom(address4, 32), netip.PrefixFrom(address6, 128)},
		DNS:             []netip.Addr{state.GatewayIPv4()},
		ServerPublicKey: state.PrivateKey.PublicKey(),
		Endpoint:        endpoint,
		AllowedIPs:      append([]string(nil), FullTunnel...),
		Keepalive:       PersistentKeepalive,
	}, nil
}

// Render writes the configuration. It is also the QR payload: the
// WireGuard apps for Android and iOS import this exact text by camera.
func (c ClientConfig) Render() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", joinStrings(c.Addresses))
	if len(c.DNS) != 0 {
		fmt.Fprintf(&b, "DNS = %s\n", joinStrings(c.DNS))
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.ServerPublicKey)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(c.AllowedIPs, ", "))
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.Keepalive)
	}
	return b.String()
}

func joinStrings[T fmt.Stringer](values []T) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = value.String()
	}
	return strings.Join(parts, ", ")
}

// ParseClientConfig reads a configuration written by Render (or a
// compatible wg-quick file with one peer).
func ParseClientConfig(text string) (ClientConfig, error) {
	var config ClientConfig
	section := ""
	peers := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			if section == "[peer]" {
				peers++
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ClientConfig{}, fmt.Errorf("configuration line %q has no value", line)
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		var err error
		switch section + key {
		case "[interface]privatekey":
			config.PrivateKey, err = ParseKey(value)
		case "[interface]address":
			for _, item := range splitList(value) {
				prefix, parseErr := netip.ParsePrefix(item)
				if parseErr != nil {
					return ClientConfig{}, fmt.Errorf("address %q is not a prefix", item)
				}
				config.Addresses = append(config.Addresses, prefix)
			}
		case "[interface]dns":
			for _, item := range splitList(value) {
				address, parseErr := netip.ParseAddr(item)
				if parseErr != nil {
					return ClientConfig{}, fmt.Errorf("DNS server %q is not an address", item)
				}
				config.DNS = append(config.DNS, address)
			}
		case "[peer]publickey":
			config.ServerPublicKey, err = ParseKey(value)
		case "[peer]allowedips":
			config.AllowedIPs = splitList(value)
		case "[peer]endpoint":
			config.Endpoint = value
		case "[peer]persistentkeepalive":
			config.Keepalive, err = strconv.Atoi(value)
		}
		if err != nil {
			return ClientConfig{}, fmt.Errorf("configuration value %s: %w", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return ClientConfig{}, err
	}
	if peers != 1 || config.PrivateKey.IsZero() || config.ServerPublicKey.IsZero() || config.Endpoint == "" || len(config.Addresses) == 0 {
		return ClientConfig{}, errors.New("the configuration needs a private key, an address and exactly one peer with a key and endpoint")
	}
	return config, nil
}

func splitList(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

var unsafeFileName = regexp.MustCompile(`[^a-z0-9]+`)

// FileName is a download name for the configuration, such as pixel-9.conf.
// The WireGuard apps use it as the tunnel name, which allows at most 15
// characters.
func FileName(name string) string {
	base := strings.Trim(unsafeFileName.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if base == "" {
		base = "shakerproxy"
	}
	if len(base) > 15 {
		base = strings.TrimRight(base[:15], "-")
	}
	return base + ".conf"
}
