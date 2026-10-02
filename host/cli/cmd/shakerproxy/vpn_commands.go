package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

// vpnAdded mirrors POST /api/v1/vpn/devices.
type vpnAdded struct {
	Peer       gatewayprotocol.VPNPeerStatus `json:"peer"`
	Config     string                        `json:"config"`
	FileName   string                        `json:"file_name"`
	DeviceID   string                        `json:"device_id"`
	DeviceName string                        `json:"device_name"`
	Warnings   []string                      `json:"warnings"`
}

func (c *cli) vpnCommand(args []string) error {
	flags := newFlags("vpn")
	passwordFile := flags.String("password-file", "", "administrator password file")
	user := flags.String("user", envOr("SHAKERPROXY_API_USERNAME", "admin"), "administrator username")
	port := flags.Int("port", 0, "UDP port devices connect to (default 51820)")
	address := flags.String("address", "", "host name or IP address (and :port) in device configurations")
	peerToPeer := flags.String("peer-to-peer", "", "on lets VPN devices reach each other")
	save := flags.String("save", "", "also write the device configuration to this file (vpn add)")
	positional, err := parseFlags("vpn", flags, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		positional = []string{"status"}
	}
	settings := map[string]any{}
	if *port != 0 {
		settings["listen_port"] = *port
	}
	if *address != "" {
		settings["endpoint"] = strings.TrimSpace(*address)
		if *address == "default" {
			settings["endpoint"] = ""
		}
	}
	if *peerToPeer != "" {
		enabled, err := onOff("vpn", *peerToPeer)
		if err != nil {
			return err
		}
		settings["allow_peer_to_peer"] = enabled
	}
	switch strings.ToLower(positional[0]) {
	case "status", "show", "list", "ls", "devices":
		if err := expectArgs("vpn", positional, 1, 1); err != nil {
			return err
		}
		return c.vpnStatus()
	case "on", "enable":
		if err := expectArgs("vpn", positional, 1, 1); err != nil {
			return err
		}
		settings["enabled"] = true
		return c.vpnSet(*user, *passwordFile, settings)
	case "off", "disable":
		if err := expectArgs("vpn", positional, 1, 1); err != nil {
			return err
		}
		settings["enabled"] = false
		return c.vpnSet(*user, *passwordFile, settings)
	case "set":
		if len(settings) == 0 {
			return usagef("vpn", "Give --address, --port or --peer-to-peer.")
		}
		return c.vpnSet(*user, *passwordFile, settings)
	case "add":
		if len(positional) < 2 {
			return usagef("vpn", "Name the device: `shakerproxy vpn add Pixel`.")
		}
		return c.vpnAdd(*user, *passwordFile, strings.Join(positional[1:], " "), *save)
	case "revoke", "remove", "rm", "delete":
		if len(positional) < 2 {
			return usagef("vpn", "Name the device to revoke: `shakerproxy vpn revoke Pixel`.")
		}
		return c.vpnRevoke(*user, *passwordFile, strings.Join(positional[1:], " "))
	}
	return usagef("vpn", "Use `shakerproxy vpn`, `vpn on`, `vpn add <name>`, `vpn revoke <name>`, `vpn set` or `vpn off`.")
}

func (c *cli) vpnStatus() error {
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	defer session.close()
	var status gatewayprotocol.VPNStatus
	raw, err := session.getJSON("/api/v1/vpn", &status)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	c.printVPNStatus(status)
	return nil
}

func (c *cli) printVPNStatus(status gatewayprotocol.VPNStatus) {
	switch {
	case !status.Enabled:
		c.printf("VPN mode  %s\n", c.style(styleYellow, "off"))
		c.println("Turn it on with `shakerproxy vpn on`, then add a phone with `shakerproxy vpn add <name>`.")
		return
	case !status.Up:
		c.printf("VPN mode  %s, but not running: %s\n", c.style(styleRed, "on"), sanitize(status.Problem))
	default:
		c.printf("VPN mode  %s  %s  (network %s)\n", c.style(styleGreen, "on"), sanitize(status.Endpoint), sanitize(status.IPv4CIDR))
	}
	if len(status.Peers) == 0 {
		c.println("No VPN devices yet. Add one with `shakerproxy vpn add <name>`.")
	} else {
		c.println()
		now := time.Now()
		for _, peer := range status.Peers {
			state := c.style(styleYellow, "not connected")
			if peer.Connected {
				state = c.style(styleGreen, "connected")
			}
			seen := "never"
			if peer.LastHandshake != nil {
				seen = humanAgoTime(now, *peer.LastHandshake)
			}
			c.printf("  %-24s %-15s %s, last handshake %s, %s in / %s out\n", sanitize(truncate(peer.Name, 24)), sanitize(peer.IPv4), state, seen, humanBytes(int64(peer.SentBytes)), humanBytes(int64(peer.ReceivedBytes)))
		}
	}
	if len(status.Notes) > 0 {
		c.println()
		for _, note := range status.Notes {
			c.printf("  %s %s\n", c.dim("•"), sanitize(note))
		}
	}
}

// vpnAdmin signs in as the administrator for a VPN change.
func (c *cli) vpnAdmin(user, passwordFile, prompt string) (*apiSession, string, error) {
	password, err := c.obtainPassword(passwordFile, false, prompt)
	if err != nil {
		return nil, "", err
	}
	admin, err := c.adminSession(user, password)
	if err != nil {
		return nil, "", err
	}
	return admin, password, nil
}

func (c *cli) vpnSet(user, passwordFile string, settings map[string]any) error {
	admin, password, err := c.vpnAdmin(user, passwordFile, "Admin password (to change VPN mode): ")
	if err != nil {
		return err
	}
	defer admin.close()
	raw, err := admin.do(http.MethodPut, "/api/v1/vpn", withPassword(settings, password))
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	var status gatewayprotocol.VPNStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return err
	}
	c.printVPNStatus(status)
	return nil
}

func (c *cli) vpnAdd(user, passwordFile, name, save string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\x00\r\n") {
		return usagef("vpn", "The device name must be 1-64 characters on one line.")
	}
	if save != "" {
		if _, err := os.Stat(filepath.Dir(save)); err != nil {
			return fmt.Errorf("cannot save to %s: %w", save, err)
		}
	}
	admin, password, err := c.vpnAdmin(user, passwordFile, "Admin password (to add a VPN device): ")
	if err != nil {
		return err
	}
	defer admin.close()
	raw, err := admin.do(http.MethodPost, "/api/v1/vpn/devices", withPassword(map[string]any{"name": name}, password))
	if err != nil {
		return err
	}
	var added vpnAdded
	if err := json.Unmarshal(raw, &added); err != nil {
		return err
	}
	if save != "" {
		if _, err := writePrivateFileAtomically(save, []byte(added.Config)); err != nil {
			return fmt.Errorf("the device was added, but its configuration could not be saved to %s: %w", save, err)
		}
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	c.printf("Added %s · %s\n\n", c.bold(sanitize(added.DeviceName)), sanitize(added.Peer.IPv4))
	c.println("  1. Install the WireGuard app on the device (App Store or Google Play).")
	c.println("  2. In WireGuard tap + and choose Scan from QR code, then scan:")
	c.println()
	if code, err := encodeQR([]byte(added.Config)); err == nil {
		code.render(c.stdout, c.color, "  ")
	} else {
		c.printf("%s\n", added.Config)
	}
	c.println()
	c.printf("  3. Turn the tunnel on. Everything the device does appears in Traffic as %q.\n\n", sanitize(added.DeviceName))
	if save != "" {
		c.printf("Saved the configuration to %s (import it in WireGuard on a laptop).\n", sanitize(save))
	}
	c.println(c.dim("The QR code holds the device's private key and is shown only now; ShakerProxy keeps only the public key."))
	c.println(c.dim("Lost it? Revoke the device and add it again."))
	for _, warning := range added.Warnings {
		c.printf("%s %s\n", c.style(styleYellow, "Note:"), sanitize(warning))
	}
	return nil
}

func (c *cli) vpnRevoke(user, passwordFile, reference string) error {
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	var status gatewayprotocol.VPNStatus
	_, err = session.getJSON("/api/v1/vpn", &status)
	session.close()
	if err != nil {
		return err
	}
	peer, err := matchVPNPeer(status.Peers, reference)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "Revoking %s (%s); it is disconnected at once.\n", sanitize(peer.Name), sanitize(peer.IPv4))
	admin, password, err := c.vpnAdmin(user, passwordFile, "Admin password (to revoke a VPN device): ")
	if err != nil {
		return err
	}
	defer admin.close()
	raw, err := admin.do(http.MethodDelete, "/api/v1/vpn/devices/"+url.PathEscape(peer.ID), withPassword(map[string]any{}, password))
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	c.printf("Revoked %s. Its traffic history stays under its name in Traffic.\n", sanitize(peer.Name))
	return nil
}

// matchVPNPeer finds a VPN device by ID, name (with or without " (VPN)") or
// address.
func matchVPNPeer(peers []gatewayprotocol.VPNPeerStatus, reference string) (gatewayprotocol.VPNPeerStatus, error) {
	reference = strings.TrimSpace(reference)
	bare := strings.TrimSpace(strings.TrimSuffix(reference, "(VPN)"))
	var matches []gatewayprotocol.VPNPeerStatus
	for _, peer := range peers {
		if peer.ID == reference || peer.IPv4 == reference || peer.IPv6 == reference || strings.EqualFold(peer.Name, bare) {
			matches = append(matches, peer)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		names := []string{}
		for _, peer := range peers {
			names = append(names, peer.Name)
		}
		if len(names) == 0 {
			return gatewayprotocol.VPNPeerStatus{}, withHints(fmt.Sprintf("no VPN device matches %q", reference), "There are no VPN devices.")
		}
		return gatewayprotocol.VPNPeerStatus{}, withHints(fmt.Sprintf("no VPN device matches %q", reference), "VPN devices: "+strings.Join(names, ", "))
	default:
		return gatewayprotocol.VPNPeerStatus{}, withHints(fmt.Sprintf("%q matches %d VPN devices", reference, len(matches)), "Use the device's VPN address or ID from `shakerproxy vpn`.")
	}
}
