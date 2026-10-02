// Package nflog reads packets the kernel logs with the iptables NFLOG target
// (nfnetlink_log). The gateway uses it to turn blocked encrypted-DNS
// attempts into Traffic events. Parsing is platform independent and bounded;
// the socket is Linux only.
package nflog

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// Netlink and nfnetlink_log constants (linux/netfilter/nfnetlink_log.h).
const (
	nlmsgHeaderLen = 16
	nfgenHeaderLen = 4
	nlmsgError     = 2
	nlmsgDone      = 3

	subsysULOG       = 4
	msgPacket        = 0
	msgConfig        = 1
	packetMsgType    = subsysULOG<<8 | msgPacket
	attrTypeMask     = 0x3fff
	attrTimestamp    = 3
	attrHardwareAddr = 8
	attrPayload      = 9
	attrPrefix       = 10

	maxMessageBytes = 64 << 10
	maxPrefixBytes  = 64
)

// Packet is one logged packet: the rule's prefix, the sender's hardware
// address when the kernel knows it, and the start of the network-layer
// packet (bounded by the rule's --nflog-size).
type Packet struct {
	Prefix       string
	HardwareAddr net.HardwareAddr
	Payload      []byte
	Time         time.Time
}

// ParseMessages decodes the NFULNL_MSG_PACKET messages in one netlink read.
// Other message types are skipped; malformed data stops the parse with an
// error and returns what was decoded before it.
func ParseMessages(data []byte, now time.Time) ([]Packet, error) {
	if len(data) > maxMessageBytes {
		return nil, errors.New("netlink read exceeds its bound")
	}
	packets := []Packet{}
	for len(data) >= nlmsgHeaderLen {
		length := int(binary.LittleEndian.Uint32(data[0:4]))
		kind := binary.LittleEndian.Uint16(data[4:6])
		if length < nlmsgHeaderLen || length > len(data) {
			return packets, errors.New("netlink message length is invalid")
		}
		message := data[nlmsgHeaderLen:length]
		if kind == packetMsgType {
			packet, err := parsePacket(message, now)
			if err != nil {
				return packets, err
			}
			packets = append(packets, packet)
		}
		next := align(length)
		if next >= len(data) {
			break
		}
		data = data[next:]
	}
	return packets, nil
}

func parsePacket(message []byte, now time.Time) (Packet, error) {
	if len(message) < nfgenHeaderLen {
		return Packet{}, errors.New("nflog message is truncated")
	}
	packet := Packet{Time: now}
	attributes := message[nfgenHeaderLen:]
	for len(attributes) >= 4 {
		length := int(binary.LittleEndian.Uint16(attributes[0:2]))
		kind := binary.LittleEndian.Uint16(attributes[2:4]) & attrTypeMask
		if length < 4 || length > len(attributes) {
			return Packet{}, errors.New("nflog attribute length is invalid")
		}
		value := attributes[4:length]
		switch kind {
		case attrPrefix:
			if len(value) > maxPrefixBytes {
				return Packet{}, errors.New("nflog prefix exceeds its bound")
			}
			if end := indexByte(value, 0); end >= 0 {
				value = value[:end]
			}
			packet.Prefix = string(value)
		case attrHardwareAddr:
			// struct nfulnl_msg_packet_hw { __be16 hw_addrlen; __u16 _pad; __u8 hw_addr[8]; }
			if len(value) >= 4 {
				addressLength := int(binary.BigEndian.Uint16(value[0:2]))
				if addressLength > 0 && addressLength <= 8 && len(value) >= 4+addressLength {
					packet.HardwareAddr = append(net.HardwareAddr(nil), value[4:4+addressLength]...)
				}
			}
		case attrPayload:
			packet.Payload = append([]byte(nil), value...)
		case attrTimestamp:
			// struct nfulnl_msg_packet_timestamp { __be64 sec; __be64 usec; }
			if len(value) >= 16 {
				seconds := int64(binary.BigEndian.Uint64(value[0:8]))
				micros := int64(binary.BigEndian.Uint64(value[8:16]))
				if seconds > 0 && micros >= 0 && micros < 1_000_000 {
					packet.Time = time.Unix(seconds, micros*1000)
				}
			}
		}
		if align(length) >= len(attributes) {
			break
		}
		attributes = attributes[align(length):]
	}
	return packet, nil
}

// Flow is the addressing of a logged IPv4 or IPv6 packet.
type Flow struct {
	Source          netip.Addr
	Destination     netip.Addr
	Protocol        string // "tcp", "udp" or "" for other protocols
	SourcePort      uint16
	DestinationPort uint16
}

// ParseFlow reads the IP header (and TCP/UDP ports) at the start of a
// logged packet. IPv6 extension headers are not followed; such packets
// report no ports.
func ParseFlow(payload []byte) (Flow, bool) {
	if len(payload) < 1 {
		return Flow{}, false
	}
	var flow Flow
	var protocol byte
	var transport []byte
	switch payload[0] >> 4 {
	case 4:
		if len(payload) < 20 {
			return Flow{}, false
		}
		headerLength := int(payload[0]&0x0f) * 4
		if headerLength < 20 || len(payload) < headerLength {
			return Flow{}, false
		}
		flow.Source = netip.AddrFrom4([4]byte(payload[12:16]))
		flow.Destination = netip.AddrFrom4([4]byte(payload[16:20]))
		protocol = payload[9]
		// Only the first fragment carries the ports.
		if binary.BigEndian.Uint16(payload[6:8])&0x1fff == 0 {
			transport = payload[headerLength:]
		}
	case 6:
		if len(payload) < 40 {
			return Flow{}, false
		}
		flow.Source = netip.AddrFrom16([16]byte(payload[8:24]))
		flow.Destination = netip.AddrFrom16([16]byte(payload[24:40]))
		protocol = payload[6]
		transport = payload[40:]
	default:
		return Flow{}, false
	}
	switch protocol {
	case 6:
		flow.Protocol = "tcp"
	case 17:
		flow.Protocol = "udp"
	}
	if flow.Protocol != "" && len(transport) >= 4 {
		flow.SourcePort = binary.BigEndian.Uint16(transport[0:2])
		flow.DestinationPort = binary.BigEndian.Uint16(transport[2:4])
	}
	return flow, true
}

func align(length int) int { return (length + 3) &^ 3 }

func indexByte(value []byte, target byte) int {
	for index, current := range value {
		if current == target {
			return index
		}
	}
	return -1
}
