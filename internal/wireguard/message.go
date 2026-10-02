// Package wireguard configures kernel WireGuard interfaces over netlink,
// with no external tools: rtnetlink creates the interface and its
// addresses, and the "wireguard" generic netlink family sets its key, port
// and peers. Message encoding is portable and unit tested; only the socket
// calls are Linux-specific.
package wireguard

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// Netlink and WireGuard constants from <linux/netlink.h>, <linux/rtnetlink.h>,
// <linux/if_link.h>, <linux/genetlink.h> and <linux/wireguard.h>.
const (
	nlmsgHeaderLength = 16
	nlmsgError        = 2
	nlmsgDone         = 3

	flagRequest = 0x1
	flagAck     = 0x4
	flagDump    = 0x300
	flagReplace = 0x100
	flagExclude = 0x200
	flagCreate  = 0x400

	attributeNested = 1 << 15

	rtmNewLink = 16
	rtmDelLink = 17
	rtmGetLink = 18
	rtmNewAddr = 20
	rtmDelAddr = 21
	rtmGetAddr = 22

	iflaIfname   = 3
	iflaMTU      = 4
	iflaLinkInfo = 18
	iflaInfoKind = 1
	iffUp        = 0x1

	ifaAddress = 1
	ifaLocal   = 2
	ifaFlags   = 8
	ifaNoDAD   = 0x2

	genlIDCtrl          = 0x10
	ctrlCmdGetFamily    = 3
	ctrlAttrFamilyID    = 1
	ctrlAttrFamilyName  = 2
	genlHeaderLength    = 4
	familyName          = "wireguard"
	genlVersion         = 1
	wgCmdGetDevice      = 0
	wgCmdSetDevice      = 1
	wgDeviceIfname      = 2
	wgDevicePrivateKey  = 3
	wgDevicePublicKey   = 4
	wgDeviceFlags       = 5
	wgDeviceListenPort  = 6
	wgDevicePeers       = 8
	wgPeerPublicKey     = 1
	wgPeerFlags         = 3
	wgPeerEndpoint      = 4
	wgPeerKeepalive     = 5
	wgPeerLastHandshake = 6
	wgPeerRxBytes       = 7
	wgPeerTxBytes       = 8
	wgPeerAllowedIPs    = 9
	wgAllowedIPFamily   = 1
	wgAllowedIPAddress  = 2
	wgAllowedIPMask     = 3
	wgPeerRemoveMe      = 1
	wgPeerReplaceIPs    = 2

	afInet  = 2
	afInet6 = 10
)

var native = binary.NativeEndian

// Peer is one desired peer. Remove deletes it instead.
type Peer struct {
	PublicKey  [32]byte
	AllowedIPs []netip.Prefix
	// Keepalive is the persistent keepalive interval in seconds, 0 for none.
	Keepalive int
	// Endpoint is optional: servers learn it from the peer's first packet.
	Endpoint netip.AddrPort
	Remove   bool
}

// Config changes a device. A nil PrivateKey or zero ListenPort leaves that
// setting alone. Peers are added or updated (their allowed IPs replaced)
// unless marked Remove; peers not listed are kept.
type Config struct {
	PrivateKey *[32]byte
	ListenPort int
	Peers      []Peer
}

// PeerStatus is a peer as the kernel reports it.
type PeerStatus struct {
	PublicKey     [32]byte
	Endpoint      netip.AddrPort
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
	AllowedIPs    []netip.Prefix
}

// Device is a WireGuard interface as the kernel reports it.
type Device struct {
	Name       string
	PrivateKey [32]byte
	PublicKey  [32]byte
	ListenPort int
	Peers      []PeerStatus
}

// Link describes a network interface.
type Link struct {
	Index int
	Kind  string
	Up    bool
	MTU   int
}

// ErrNotFound means the interface does not exist.
var ErrNotFound = errors.New("interface not found")

// ErrUnsupported means the kernel has no WireGuard support (or the
// platform is not Linux).
var ErrUnsupported = errors.New("this system has no kernel WireGuard support (Linux module wireguard)")

// attributes builds a netlink attribute list.
type attributes []byte

func align4(length int) int { return (length + 3) &^ 3 }

func (a *attributes) add(kind uint16, value []byte) {
	header := make([]byte, 4)
	native.PutUint16(header[0:2], uint16(4+len(value)))
	native.PutUint16(header[2:4], kind)
	*a = append(*a, header...)
	*a = append(*a, value...)
	for len(*a)%4 != 0 {
		*a = append(*a, 0)
	}
}

func (a *attributes) addNested(kind uint16, nested attributes) {
	a.add(kind|attributeNested, nested)
}

func (a *attributes) addString(kind uint16, value string) {
	a.add(kind, append([]byte(value), 0))
}

func (a *attributes) addUint16(kind uint16, value uint16) {
	raw := make([]byte, 2)
	native.PutUint16(raw, value)
	a.add(kind, raw)
}

func (a *attributes) addUint32(kind uint16, value uint32) {
	raw := make([]byte, 4)
	native.PutUint32(raw, value)
	a.add(kind, raw)
}

// attribute is one parsed netlink attribute.
type attribute struct {
	kind  uint16
	value []byte
}

func parseAttributes(data []byte) ([]attribute, error) {
	var result []attribute
	for len(data) >= 4 {
		length := int(native.Uint16(data[0:2]))
		if length < 4 || length > len(data) {
			return nil, errors.New("malformed netlink attribute")
		}
		result = append(result, attribute{kind: native.Uint16(data[2:4]) &^ (attributeNested | 1<<14), value: data[4:length]})
		next := align4(length)
		if next > len(data) {
			break
		}
		data = data[next:]
	}
	return result, nil
}

// message builds one netlink message.
func message(kind, flags uint16, sequence uint32, body []byte) []byte {
	raw := make([]byte, nlmsgHeaderLength, nlmsgHeaderLength+len(body))
	native.PutUint32(raw[0:4], uint32(nlmsgHeaderLength+len(body)))
	native.PutUint16(raw[4:6], kind)
	native.PutUint16(raw[6:8], flags)
	native.PutUint32(raw[8:12], sequence)
	return append(raw, body...)
}

// netlinkMessage is one received message.
type netlinkMessage struct {
	kind     uint16
	sequence uint32
	body     []byte
}

func parseMessages(data []byte) ([]netlinkMessage, error) {
	var result []netlinkMessage
	for len(data) >= nlmsgHeaderLength {
		length := int(native.Uint32(data[0:4]))
		if length < nlmsgHeaderLength || length > len(data) {
			return nil, errors.New("malformed netlink message")
		}
		result = append(result, netlinkMessage{kind: native.Uint16(data[4:6]), sequence: native.Uint32(data[8:12]), body: data[nlmsgHeaderLength:length]})
		next := align4(length)
		if next > len(data) {
			break
		}
		data = data[next:]
	}
	return result, nil
}

// genlBody prefixes generic netlink attributes with the genl header.
func genlBody(command uint8, attrs attributes) []byte {
	return append([]byte{command, genlVersion, 0, 0}, attrs...)
}

// setDeviceMessages encodes a WG_CMD_SET_DEVICE request body per message:
// peers are split so no message grows beyond a page, like wg(8) does.
func setDeviceMessages(name string, config Config) [][]byte {
	const peersPerMessage = 16
	device := func() attributes {
		var attrs attributes
		attrs.addString(wgDeviceIfname, name)
		return attrs
	}
	first := device()
	if config.PrivateKey != nil {
		first.add(wgDevicePrivateKey, config.PrivateKey[:])
	}
	if config.ListenPort != 0 {
		first.addUint16(wgDeviceListenPort, uint16(config.ListenPort))
	}
	var bodies [][]byte
	peers := config.Peers
	current := first
	for {
		count := min(peersPerMessage, len(peers))
		if count > 0 {
			var list attributes
			for index, peer := range peers[:count] {
				list.addNested(uint16(index), encodePeer(peer))
			}
			current.addNested(wgDevicePeers, list)
		}
		bodies = append(bodies, genlBody(wgCmdSetDevice, current))
		peers = peers[count:]
		if len(peers) == 0 {
			return bodies
		}
		current = device()
	}
}

func encodePeer(peer Peer) attributes {
	var attrs attributes
	attrs.add(wgPeerPublicKey, peer.PublicKey[:])
	if peer.Remove {
		attrs.addUint32(wgPeerFlags, wgPeerRemoveMe)
		return attrs
	}
	attrs.addUint32(wgPeerFlags, wgPeerReplaceIPs)
	attrs.addUint16(wgPeerKeepalive, uint16(peer.Keepalive))
	if peer.Endpoint.IsValid() {
		attrs.add(wgPeerEndpoint, encodeSockaddr(peer.Endpoint))
	}
	var allowed attributes
	for index, prefix := range peer.AllowedIPs {
		var ip attributes
		family := uint16(afInet)
		if prefix.Addr().Is6() {
			family = afInet6
		}
		ip.addUint16(wgAllowedIPFamily, family)
		ip.add(wgAllowedIPAddress, prefix.Masked().Addr().AsSlice())
		ip.add(wgAllowedIPMask, []byte{byte(prefix.Bits())})
		allowed.addNested(uint16(index), ip)
	}
	attrs.addNested(wgPeerAllowedIPs, allowed)
	return attrs
}

func encodeSockaddr(endpoint netip.AddrPort) []byte {
	address := endpoint.Addr()
	if address.Is4() || address.Is4In6() {
		raw := make([]byte, 16)
		native.PutUint16(raw[0:2], afInet)
		binary.BigEndian.PutUint16(raw[2:4], endpoint.Port())
		bytes := address.Unmap().As4()
		copy(raw[4:8], bytes[:])
		return raw
	}
	raw := make([]byte, 28)
	native.PutUint16(raw[0:2], afInet6)
	binary.BigEndian.PutUint16(raw[2:4], endpoint.Port())
	bytes := address.As16()
	copy(raw[8:24], bytes[:])
	return raw
}

func decodeSockaddr(raw []byte) netip.AddrPort {
	if len(raw) < 4 {
		return netip.AddrPort{}
	}
	port := binary.BigEndian.Uint16(raw[2:4])
	switch native.Uint16(raw[0:2]) {
	case afInet:
		if len(raw) >= 8 {
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[4:8])), port)
		}
	case afInet6:
		if len(raw) >= 24 {
			return netip.AddrPortFrom(netip.AddrFrom16([16]byte(raw[8:24])), port)
		}
	}
	return netip.AddrPort{}
}

// parseDeviceMessage merges one WG_CMD_GET_DEVICE reply into device. A
// device with many peers arrives over several messages.
func parseDeviceMessage(body []byte, device *Device) error {
	if len(body) < genlHeaderLength {
		return errors.New("short WireGuard reply")
	}
	attrs, err := parseAttributes(body[genlHeaderLength:])
	if err != nil {
		return err
	}
	for _, attr := range attrs {
		switch attr.kind {
		case wgDeviceIfname:
			device.Name = cString(attr.value)
		case wgDevicePrivateKey:
			if len(attr.value) == 32 {
				copy(device.PrivateKey[:], attr.value)
			}
		case wgDevicePublicKey:
			if len(attr.value) == 32 {
				copy(device.PublicKey[:], attr.value)
			}
		case wgDeviceListenPort:
			if len(attr.value) >= 2 {
				device.ListenPort = int(native.Uint16(attr.value))
			}
		case wgDevicePeers:
			peers, err := parseAttributes(attr.value)
			if err != nil {
				return err
			}
			for _, entry := range peers {
				peer, err := parsePeer(entry.value)
				if err != nil {
					return err
				}
				// A peer split across messages repeats its key.
				if count := len(device.Peers); count > 0 && device.Peers[count-1].PublicKey == peer.PublicKey {
					device.Peers[count-1].AllowedIPs = append(device.Peers[count-1].AllowedIPs, peer.AllowedIPs...)
					continue
				}
				device.Peers = append(device.Peers, peer)
			}
		}
	}
	return nil
}

func parsePeer(data []byte) (PeerStatus, error) {
	var peer PeerStatus
	attrs, err := parseAttributes(data)
	if err != nil {
		return peer, err
	}
	for _, attr := range attrs {
		switch attr.kind {
		case wgPeerPublicKey:
			if len(attr.value) == 32 {
				copy(peer.PublicKey[:], attr.value)
			}
		case wgPeerEndpoint:
			peer.Endpoint = decodeSockaddr(attr.value)
		case wgPeerLastHandshake:
			if len(attr.value) >= 16 {
				seconds, nanoseconds := int64(native.Uint64(attr.value[0:8])), int64(native.Uint64(attr.value[8:16]))
				if seconds != 0 || nanoseconds != 0 {
					peer.LastHandshake = time.Unix(seconds, nanoseconds).UTC()
				}
			}
		case wgPeerRxBytes:
			if len(attr.value) >= 8 {
				peer.RxBytes = native.Uint64(attr.value)
			}
		case wgPeerTxBytes:
			if len(attr.value) >= 8 {
				peer.TxBytes = native.Uint64(attr.value)
			}
		case wgPeerAllowedIPs:
			entries, err := parseAttributes(attr.value)
			if err != nil {
				return peer, err
			}
			for _, entry := range entries {
				if prefix, ok := parseAllowedIP(entry.value); ok {
					peer.AllowedIPs = append(peer.AllowedIPs, prefix)
				}
			}
		}
	}
	return peer, nil
}

func parseAllowedIP(data []byte) (netip.Prefix, bool) {
	attrs, err := parseAttributes(data)
	if err != nil {
		return netip.Prefix{}, false
	}
	var address netip.Addr
	mask := -1
	for _, attr := range attrs {
		switch attr.kind {
		case wgAllowedIPAddress:
			address, _ = netip.AddrFromSlice(attr.value)
		case wgAllowedIPMask:
			if len(attr.value) >= 1 {
				mask = int(attr.value[0])
			}
		}
	}
	if !address.IsValid() || mask < 0 {
		return netip.Prefix{}, false
	}
	prefix, err := address.Prefix(mask)
	return prefix, err == nil
}

func cString(raw []byte) string {
	for index, value := range raw {
		if value == 0 {
			return string(raw[:index])
		}
	}
	return string(raw)
}

// ifinfo encodes struct ifinfomsg.
func ifinfo(index int, flags, change uint32) []byte {
	raw := make([]byte, 16)
	native.PutUint32(raw[4:8], uint32(int32(index)))
	native.PutUint32(raw[8:12], flags)
	native.PutUint32(raw[12:16], change)
	return raw
}

// ifaddr encodes struct ifaddrmsg plus the address attributes.
func ifaddr(index int, prefix netip.Prefix) []byte {
	raw := make([]byte, 8)
	family := byte(afInet)
	if prefix.Addr().Is6() {
		family = afInet6
	}
	raw[0], raw[1] = family, byte(prefix.Bits())
	native.PutUint32(raw[4:8], uint32(index))
	var attrs attributes
	address := prefix.Addr().AsSlice()
	attrs.add(ifaLocal, address)
	attrs.add(ifaAddress, address)
	if family == afInet6 {
		attrs.addUint32(ifaFlags, ifaNoDAD)
	}
	return append(raw, attrs...)
}

// parseLink decodes an RTM_NEWLINK reply.
func parseLink(body []byte) (Link, string, error) {
	if len(body) < 16 {
		return Link{}, "", errors.New("short link reply")
	}
	link := Link{Index: int(int32(native.Uint32(body[4:8]))), Up: native.Uint32(body[8:12])&iffUp != 0}
	attrs, err := parseAttributes(body[16:])
	if err != nil {
		return Link{}, "", err
	}
	name := ""
	for _, attr := range attrs {
		switch attr.kind {
		case iflaIfname:
			name = cString(attr.value)
		case iflaMTU:
			if len(attr.value) >= 4 {
				link.MTU = int(native.Uint32(attr.value))
			}
		case iflaLinkInfo:
			info, err := parseAttributes(attr.value)
			if err != nil {
				return Link{}, "", err
			}
			for _, item := range info {
				if item.kind == iflaInfoKind {
					link.Kind = cString(item.value)
				}
			}
		}
	}
	return link, name, nil
}

// parseAddress decodes an RTM_NEWADDR reply into its interface index and
// prefix.
func parseAddress(body []byte) (int, netip.Prefix, bool) {
	if len(body) < 8 {
		return 0, netip.Prefix{}, false
	}
	bits, index := int(body[1]), int(native.Uint32(body[4:8]))
	attrs, err := parseAttributes(body[8:])
	if err != nil {
		return 0, netip.Prefix{}, false
	}
	var local, address netip.Addr
	for _, attr := range attrs {
		switch attr.kind {
		case ifaLocal:
			local, _ = netip.AddrFromSlice(attr.value)
		case ifaAddress:
			address, _ = netip.AddrFromSlice(attr.value)
		}
	}
	if local.IsValid() {
		address = local
	}
	if !address.IsValid() {
		return 0, netip.Prefix{}, false
	}
	prefix, err := address.Prefix(bits)
	if err != nil {
		return 0, netip.Prefix{}, false
	}
	return index, netip.PrefixFrom(address, prefix.Bits()), true
}
