package wireguard

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func key(value byte) [32]byte {
	var k [32]byte
	for index := range k {
		k[index] = value
	}
	return k
}

// findAttribute returns the first attribute of a kind.
func findAttribute(t *testing.T, data []byte, kind uint16) []byte {
	t.Helper()
	attrs, err := parseAttributes(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, attr := range attrs {
		if attr.kind == kind {
			return attr.value
		}
	}
	t.Fatalf("attribute %d missing", kind)
	return nil
}

func TestSetDeviceEncodesKeyPortAndPeers(t *testing.T) {
	private := key(7)
	peers := []Peer{
		{PublicKey: key(1), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.89.0.2/32"), netip.MustParsePrefix("fd12::2/128")}},
		{PublicKey: key(2), Remove: true},
	}
	bodies := setDeviceMessages("wg-lab", Config{PrivateKey: &private, ListenPort: 51820, Peers: peers})
	if len(bodies) != 1 {
		t.Fatalf("got %d messages", len(bodies))
	}
	body := bodies[0]
	if body[0] != wgCmdSetDevice || body[1] != genlVersion {
		t.Fatalf("genl header % x", body[:4])
	}
	attrs := body[genlHeaderLength:]
	if cString(findAttribute(t, attrs, wgDeviceIfname)) != "wg-lab" || !bytes.Equal(findAttribute(t, attrs, wgDevicePrivateKey), private[:]) || native.Uint16(findAttribute(t, attrs, wgDeviceListenPort)) != 51820 {
		t.Fatal("device attributes are wrong")
	}
	list, err := parseAttributes(findAttribute(t, attrs, wgDevicePeers))
	if err != nil || len(list) != 2 {
		t.Fatalf("peers %d %v", len(list), err)
	}
	first := list[0].value
	if !bytes.Equal(findAttribute(t, first, wgPeerPublicKey), peers[0].PublicKey[:]) || native.Uint32(findAttribute(t, first, wgPeerFlags)) != wgPeerReplaceIPs {
		t.Fatal("first peer is wrong")
	}
	allowed, _ := parseAttributes(findAttribute(t, first, wgPeerAllowedIPs))
	if len(allowed) != 2 {
		t.Fatalf("allowed IPs %d", len(allowed))
	}
	if prefix, ok := parseAllowedIP(allowed[1].value); !ok || prefix != netip.MustParsePrefix("fd12::2/128") {
		t.Fatalf("second allowed IP %v", prefix)
	}
	if native.Uint32(findAttribute(t, list[1].value, wgPeerFlags)) != wgPeerRemoveMe {
		t.Fatal("removed peer lacks REMOVE_ME")
	}
}

func TestManyPeersAreSplitAcrossMessages(t *testing.T) {
	peers := make([]Peer, 40)
	for index := range peers {
		peers[index] = Peer{PublicKey: key(byte(index + 1)), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.89.0.2/32")}}
	}
	bodies := setDeviceMessages("wg-lab", Config{Peers: peers})
	if len(bodies) != 3 {
		t.Fatalf("40 peers in %d messages", len(bodies))
	}
	total := 0
	for index, body := range bodies {
		attrs := body[genlHeaderLength:]
		if cString(findAttribute(t, attrs, wgDeviceIfname)) != "wg-lab" {
			t.Fatalf("message %d has no interface name", index)
		}
		list, _ := parseAttributes(findAttribute(t, attrs, wgDevicePeers))
		total += len(list)
	}
	if total != 40 {
		t.Fatalf("encoded %d peers", total)
	}
}

func TestDeviceDumpIsParsed(t *testing.T) {
	var allowed attributes
	var ip attributes
	ip.addUint16(wgAllowedIPFamily, afInet)
	ip.add(wgAllowedIPAddress, []byte{10, 89, 0, 2})
	ip.add(wgAllowedIPMask, []byte{32})
	allowed.addNested(0, ip)
	var peer attributes
	peer.add(wgPeerPublicKey, bytes.Repeat([]byte{1}, 32))
	peer.add(wgPeerEndpoint, encodeSockaddr(netip.MustParseAddrPort("203.0.113.7:41820")))
	handshake := make([]byte, 16)
	native.PutUint64(handshake[0:8], uint64(time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC).Unix()))
	peer.add(wgPeerLastHandshake, handshake)
	rx := make([]byte, 8)
	native.PutUint64(rx, 1234)
	peer.add(wgPeerRxBytes, rx)
	peer.addNested(wgPeerAllowedIPs, allowed)
	var peers attributes
	peers.addNested(0, peer)
	var device attributes
	device.addString(wgDeviceIfname, "wg-lab")
	device.addUint16(wgDeviceListenPort, 51820)
	device.add(wgDevicePublicKey, bytes.Repeat([]byte{9}, 32))
	device.addNested(wgDevicePeers, peers)
	var parsed Device
	if err := parseDeviceMessage(genlBody(wgCmdGetDevice, device), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Name != "wg-lab" || parsed.ListenPort != 51820 || parsed.PublicKey != key(9) || len(parsed.Peers) != 1 {
		t.Fatalf("device = %+v", parsed)
	}
	got := parsed.Peers[0]
	if got.PublicKey != key(1) || got.Endpoint.String() != "203.0.113.7:41820" || got.RxBytes != 1234 || got.LastHandshake.Year() != 2026 || len(got.AllowedIPs) != 1 || got.AllowedIPs[0].String() != "10.89.0.2/32" {
		t.Fatalf("peer = %+v", got)
	}
	// A peer continued in the next message only adds allowed IPs.
	if err := parseDeviceMessage(genlBody(wgCmdGetDevice, device), &parsed); err != nil || len(parsed.Peers) != 1 || len(parsed.Peers[0].AllowedIPs) != 2 {
		t.Fatalf("continued peer: %+v %v", parsed.Peers, err)
	}
}

func TestSockaddrsAndAddresses(t *testing.T) {
	for _, text := range []string{"192.168.10.177:51820", "[2001:db8::7]:443"} {
		endpoint := netip.MustParseAddrPort(text)
		if decoded := decodeSockaddr(encodeSockaddr(endpoint)); decoded != endpoint {
			t.Fatalf("%s decoded as %s", endpoint, decoded)
		}
	}
	for _, text := range []string{"10.89.0.1/24", "fd12:3456:789a:1::1/64"} {
		prefix := netip.MustParsePrefix(text)
		index, decoded, ok := parseAddress(ifaddr(7, prefix))
		if !ok || index != 7 || decoded != prefix {
			t.Fatalf("%s decoded as %d %s %v", prefix, index, decoded, ok)
		}
	}
	var info attributes
	info.addString(iflaInfoKind, "wireguard")
	var attrs attributes
	attrs.addString(iflaIfname, "wg-lab")
	attrs.addUint32(iflaMTU, 1420)
	attrs.addNested(iflaLinkInfo, info)
	link, name, err := parseLink(append(ifinfo(12, iffUp, 0), attrs...))
	if err != nil || name != "wg-lab" || link.Kind != "wireguard" || !link.Up || link.MTU != 1420 || link.Index != 12 {
		t.Fatalf("link = %+v %q %v", link, name, err)
	}
	messages, err := parseMessages(append(message(rtmNewLink, flagRequest, 5, []byte{1, 2, 3, 4}), message(nlmsgDone, 0, 5, nil)...))
	if err != nil || len(messages) != 2 || messages[0].sequence != 5 || messages[1].kind != nlmsgDone {
		t.Fatalf("messages %+v %v", messages, err)
	}
}
