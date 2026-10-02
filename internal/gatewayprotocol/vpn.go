package gatewayprotocol

import "time"

// VPNStatus answers GetVPN: VPN mode's settings, its devices and whether
// they are connected. It never contains a private key.
type VPNStatus struct {
	Schema   int    `json:"schema"`
	Revision uint64 `json:"revision"`
	Enabled  bool   `json:"enabled"`
	// Up is true when the WireGuard interface is running as configured.
	Up        bool   `json:"up"`
	Interface string `json:"interface"`
	// ListenPort is the UDP port ShakerProxy listens on.
	ListenPort int `json:"listen_port"`
	// Endpoint is what device configurations dial (host:port);
	// EndpointSetting is the administrator's override, empty for the
	// default (DefaultEndpointHost and ListenPort).
	Endpoint            string `json:"endpoint,omitempty"`
	EndpointSetting     string `json:"endpoint_setting,omitempty"`
	DefaultEndpointHost string `json:"default_endpoint_host,omitempty"`
	ServerPublicKey     string `json:"server_public_key"`
	IPv4CIDR            string `json:"ipv4_cidr"`
	GatewayIPv4         string `json:"gateway_ipv4"`
	IPv6Prefix          string `json:"ipv6_prefix"`
	GatewayIPv6         string `json:"gateway_ipv6"`
	// IPv6Routed is true when VPN devices' IPv6 reaches the internet
	// (NAT66); otherwise IPv6 stays inside the tunnel and devices use IPv4.
	IPv6Routed      bool            `json:"ipv6_routed"`
	AllowPeerToPeer bool            `json:"allow_peer_to_peer"`
	Peers           []VPNPeerStatus `json:"peers"`
	// Problem explains why an enabled VPN is not up.
	Problem string `json:"problem,omitempty"`
	// Notes are plain-language facts a tester needs (port forwarding,
	// IPv6, who can reach whom).
	Notes []string `json:"notes"`
}

// VPNPeerStatus is one VPN device.
type VPNPeerStatus struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	DeviceID  string    `json:"device_id,omitempty"`
	PublicKey string    `json:"public_key"`
	IPv4      string    `json:"ipv4"`
	IPv6      string    `json:"ipv6"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	// Connected is true after a handshake within the last three minutes.
	Connected     bool       `json:"connected"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	// RemoteAddress is where the device last connected from.
	RemoteAddress string `json:"remote_address,omitempty"`
	ReceivedBytes uint64 `json:"received_bytes"`
	SentBytes     uint64 `json:"sent_bytes"`
}

// SetVPNParams turns VPN mode on or off and changes its settings.
type SetVPNParams struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Enabled          bool   `json:"enabled"`
	ListenPort       int    `json:"listen_port"`
	Endpoint         string `json:"endpoint"`
	IPv4CIDR         string `json:"ipv4_cidr"`
	AllowPeerToPeer  bool   `json:"allow_peer_to_peer"`
}

// AddVPNPeerParams adds a device.
type AddVPNPeerParams struct {
	Name  string `json:"name"`
	Actor string `json:"actor,omitempty"`
}

// VPNPeerConfig answers AddVPNPeer. Config holds the device's private key
// and is shown once: ShakerProxy keeps only the public key.
type VPNPeerConfig struct {
	Peer     VPNPeerStatus `json:"peer"`
	Config   string        `json:"config"`
	FileName string        `json:"file_name"`
}

// SetVPNPeerDeviceParams records which inventory device a peer is.
type SetVPNPeerDeviceParams struct {
	PeerID   string `json:"peer_id"`
	DeviceID string `json:"device_id"`
}

// RevokeVPNPeerParams removes a device; it is disconnected at once.
type RevokeVPNPeerParams struct {
	PeerID string `json:"peer_id"`
}
