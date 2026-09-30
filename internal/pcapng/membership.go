package pcapng

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

const (
	MembershipSchema      = 1
	MaxObservedIdentities = 4096
	maxInterfaces         = 256
	maxBlockBytes         = 2 << 20
	maxCapturedPacket     = 1 << 20
)

type MembershipState string

const (
	MembershipExact               MembershipState = "EXACT"
	MembershipInvalidPCAPNG       MembershipState = "INVALID_PCAPNG"
	MembershipUnsupportedLinkType MembershipState = "UNSUPPORTED_LINK_TYPE"
	MembershipPacketHeaders       MembershipState = "PACKET_HEADERS_UNAVAILABLE"
	MembershipIdentityLimit       MembershipState = "IDENTITY_LIMIT_EXCEEDED"
)

var ErrInvalidPCAPNG = errors.New("invalid PCAPNG")

type Membership struct {
	Schema       int             `json:"schema"`
	State        MembershipState `json:"state"`
	PacketCount  uint64          `json:"packet_count"`
	LinkTypes    []uint16        `json:"link_types"`
	MACAddresses []string        `json:"mac_addresses"`
	IPAddresses  []string        `json:"ip_addresses"`
}

func Unavailable(state MembershipState) Membership {
	return Membership{Schema: MembershipSchema, State: state, LinkTypes: []uint16{}, MACAddresses: []string{}, IPAddresses: []string{}}
}

func (m Membership) Exact() bool { return m.Schema == MembershipSchema && m.State == MembershipExact }

func (m Membership) Validate() error {
	if m.Schema != MembershipSchema || m.PacketCount > 1<<40 || len(m.LinkTypes) > maxInterfaces || len(m.MACAddresses)+len(m.IPAddresses) > MaxObservedIdentities {
		return errors.New("PCAP membership is invalid")
	}
	switch m.State {
	case MembershipExact, MembershipInvalidPCAPNG, MembershipUnsupportedLinkType, MembershipPacketHeaders, MembershipIdentityLimit:
	default:
		return errors.New("PCAP membership state is invalid")
	}
	if m.State == MembershipInvalidPCAPNG && (m.PacketCount != 0 || len(m.LinkTypes) != 0 || len(m.MACAddresses) != 0 || len(m.IPAddresses) != 0) {
		return errors.New("invalid PCAP membership contains observations")
	}
	var previous uint16
	for index, linkType := range m.LinkTypes {
		if index > 0 && linkType <= previous {
			return errors.New("PCAP membership link types are not unique and sorted")
		}
		previous = linkType
		if m.State == MembershipExact && linkType != 1 && linkType != 101 {
			return errors.New("exact PCAP membership contains an unsupported link type")
		}
	}
	if !sortedUnique(m.MACAddresses) || !sortedUnique(m.IPAddresses) {
		return errors.New("PCAP membership identities are not unique and sorted")
	}
	for _, value := range m.MACAddresses {
		if canonicalMAC(value) != value {
			return errors.New("PCAP membership contains a non-canonical MAC address")
		}
	}
	for _, value := range m.IPAddresses {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Unmap().String() != value || !observableIP(address) {
			return errors.New("PCAP membership contains a non-canonical IP address")
		}
	}
	return nil
}

func Inspect(reader io.Reader) (Membership, error) {
	if reader == nil {
		return Membership{}, fmt.Errorf("%w: reader is unavailable", ErrInvalidPCAPNG)
	}
	collector := membershipCollector{membership: Membership{Schema: MembershipSchema, State: MembershipExact}, linkTypes: map[uint16]struct{}{}, macs: map[string]struct{}{}, ips: map[string]struct{}{}}
	if err := scan(reader, collector.observe); err != nil {
		return Membership{}, err
	}
	collector.finish()
	if err := collector.membership.Validate(); err != nil {
		return Membership{}, fmt.Errorf("%w: %v", ErrInvalidPCAPNG, err)
	}
	return collector.membership, nil
}

type packetObservation struct {
	linkType uint16
	data     []byte
}

type packetObserver func(packetObservation)

type membershipCollector struct {
	membership         Membership
	linkTypes          map[uint16]struct{}
	macs               map[string]struct{}
	ips                map[string]struct{}
	overflow           bool
	unsupported        bool
	headersUnavailable bool
}

func (c *membershipCollector) observe(packet packetObservation) {
	c.membership.PacketCount++
	c.linkTypes[packet.linkType] = struct{}{}
	identities, limitation := packetIdentities(packet.linkType, packet.data)
	switch limitation {
	case MembershipUnsupportedLinkType:
		c.unsupported = true
	case MembershipPacketHeaders:
		c.headersUnavailable = true
	}
	for _, mac := range identities.macs {
		if _, exists := c.macs[mac]; exists {
			continue
		}
		if len(c.macs)+len(c.ips) >= MaxObservedIdentities {
			c.overflow = true
			continue
		}
		c.macs[mac] = struct{}{}
	}
	for _, address := range identities.ips {
		if _, exists := c.ips[address]; exists {
			continue
		}
		if len(c.macs)+len(c.ips) >= MaxObservedIdentities {
			c.overflow = true
			continue
		}
		c.ips[address] = struct{}{}
	}
}

func (c *membershipCollector) finish() {
	for linkType := range c.linkTypes {
		c.membership.LinkTypes = append(c.membership.LinkTypes, linkType)
	}
	for mac := range c.macs {
		c.membership.MACAddresses = append(c.membership.MACAddresses, mac)
	}
	for address := range c.ips {
		c.membership.IPAddresses = append(c.membership.IPAddresses, address)
	}
	sort.Slice(c.membership.LinkTypes, func(i, j int) bool { return c.membership.LinkTypes[i] < c.membership.LinkTypes[j] })
	sort.Strings(c.membership.MACAddresses)
	sort.Strings(c.membership.IPAddresses)
	if c.unsupported {
		c.membership.State = MembershipUnsupportedLinkType
	} else if c.headersUnavailable {
		c.membership.State = MembershipPacketHeaders
	} else if c.overflow {
		c.membership.State = MembershipIdentityLimit
	}
}

type sectionState struct {
	order      binary.ByteOrder
	interfaces []uint16
}

func scan(reader io.Reader, observe packetObserver) error {
	var section *sectionState
	for {
		block, blockType, order, err := readBlock(reader, section)
		if errors.Is(err, io.EOF) {
			if section == nil {
				return fmt.Errorf("%w: section header is absent", ErrInvalidPCAPNG)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if blockType == 0x0a0d0d0a {
			if order.Uint16(block[12:14]) != 1 || order.Uint16(block[14:16]) != 0 {
				return fmt.Errorf("%w: section version is unsupported", ErrInvalidPCAPNG)
			}
			section = &sectionState{order: order}
			continue
		}
		if section == nil {
			return fmt.Errorf("%w: data precedes the section header", ErrInvalidPCAPNG)
		}
		switch blockType {
		case 1:
			if len(block) < 20 || len(section.interfaces) >= maxInterfaces {
				return fmt.Errorf("%w: interface block is invalid", ErrInvalidPCAPNG)
			}
			section.interfaces = append(section.interfaces, section.order.Uint16(block[8:10]))
		case 2:
			if len(block) < 32 {
				return fmt.Errorf("%w: packet block is truncated", ErrInvalidPCAPNG)
			}
			interfaceID := uint32(section.order.Uint16(block[8:10]))
			captured := section.order.Uint32(block[20:24])
			original := section.order.Uint32(block[24:28])
			packet, err := packetData(block, 28, captured)
			if err != nil || captured > original || interfaceID >= uint32(len(section.interfaces)) {
				return fmt.Errorf("%w: packet block is invalid", ErrInvalidPCAPNG)
			}
			observe(packetObservation{linkType: section.interfaces[interfaceID], data: packet})
		case 3:
			if len(block) < 16 || len(section.interfaces) == 0 {
				return fmt.Errorf("%w: simple packet block is invalid", ErrInvalidPCAPNG)
			}
			original := section.order.Uint32(block[8:12])
			available := uint32(len(block) - 16)
			captured := original
			if captured > available {
				captured = available
			}
			if captured > maxCapturedPacket {
				return fmt.Errorf("%w: simple packet exceeds its bound", ErrInvalidPCAPNG)
			}
			observe(packetObservation{linkType: section.interfaces[0], data: block[12 : 12+captured]})
		case 6:
			if len(block) < 32 {
				return fmt.Errorf("%w: enhanced packet block is truncated", ErrInvalidPCAPNG)
			}
			interfaceID := section.order.Uint32(block[8:12])
			captured := section.order.Uint32(block[20:24])
			original := section.order.Uint32(block[24:28])
			packet, err := packetData(block, 28, captured)
			if err != nil || captured > original || interfaceID >= uint32(len(section.interfaces)) {
				return fmt.Errorf("%w: enhanced packet block is invalid", ErrInvalidPCAPNG)
			}
			observe(packetObservation{linkType: section.interfaces[interfaceID], data: packet})
		}
	}
}

func readBlock(reader io.Reader, section *sectionState) ([]byte, uint32, binary.ByteOrder, error) {
	header := make([]byte, 12)
	if _, err := io.ReadFull(reader, header[:4]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, 0, nil, io.EOF
		}
		return nil, 0, nil, fmt.Errorf("%w: truncated block type", ErrInvalidPCAPNG)
	}
	if _, err := io.ReadFull(reader, header[4:]); err != nil {
		return nil, 0, nil, fmt.Errorf("%w: truncated block header", ErrInvalidPCAPNG)
	}
	blockType := uint32(0)
	var order binary.ByteOrder
	if string(header[:4]) == "\x0a\x0d\x0d\x0a" {
		blockType = 0x0a0d0d0a
		switch string(header[8:12]) {
		case "\x4d\x3c\x2b\x1a":
			order = binary.LittleEndian
		case "\x1a\x2b\x3c\x4d":
			order = binary.BigEndian
		default:
			return nil, 0, nil, fmt.Errorf("%w: byte-order magic is invalid", ErrInvalidPCAPNG)
		}
	} else {
		if section == nil {
			return nil, 0, nil, fmt.Errorf("%w: first block is not a section header", ErrInvalidPCAPNG)
		}
		order = section.order
		blockType = order.Uint32(header[:4])
	}
	total := order.Uint32(header[4:8])
	minimum := uint32(12)
	if blockType == 0x0a0d0d0a {
		minimum = 28
	}
	if total < minimum || total%4 != 0 || total > maxBlockBytes {
		return nil, 0, nil, fmt.Errorf("%w: block length is invalid", ErrInvalidPCAPNG)
	}
	block := make([]byte, total)
	copy(block, header)
	if _, err := io.ReadFull(reader, block[12:]); err != nil {
		return nil, 0, nil, fmt.Errorf("%w: block body is truncated", ErrInvalidPCAPNG)
	}
	if order.Uint32(block[len(block)-4:]) != total {
		return nil, 0, nil, fmt.Errorf("%w: block lengths disagree", ErrInvalidPCAPNG)
	}
	return block, blockType, order, nil
}

func packetData(block []byte, offset int, captured uint32) ([]byte, error) {
	if captured > maxCapturedPacket {
		return nil, errors.New("captured packet exceeds its bound")
	}
	padded := (uint64(captured) + 3) &^ 3
	if uint64(offset)+padded+4 > uint64(len(block)) {
		return nil, errors.New("captured packet is truncated")
	}
	return block[offset : offset+int(captured)], nil
}

type identities struct {
	macs []string
	ips  []string
}

func packetIdentities(linkType uint16, packet []byte) (identities, MembershipState) {
	switch linkType {
	case 1:
		return ethernetIdentities(packet)
	case 101:
		return ipIdentities(packet)
	default:
		return identities{}, MembershipUnsupportedLinkType
	}
}

func ethernetIdentities(packet []byte) (identities, MembershipState) {
	var result identities
	if len(packet) < 14 {
		return result, MembershipPacketHeaders
	}
	result.macs = appendObservableMAC(result.macs, packet[0:6])
	result.macs = appendObservableMAC(result.macs, packet[6:12])
	etherType := binary.BigEndian.Uint16(packet[12:14])
	offset := 14
	for tags := 0; tags < 4 && (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100); tags++ {
		if len(packet) < offset+4 {
			return result, MembershipPacketHeaders
		}
		etherType = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		offset += 4
	}
	if len(packet) < offset {
		return result, MembershipPacketHeaders
	}
	switch etherType {
	case 0x0800, 0x86dd:
		ip, limitation := ipIdentities(packet[offset:])
		result.ips = append(result.ips, ip.ips...)
		if limitation != "" {
			return result, limitation
		}
	case 0x0806:
		if len(packet) < offset+8 {
			return result, MembershipPacketHeaders
		}
		if binary.BigEndian.Uint16(packet[offset:offset+2]) == 1 && binary.BigEndian.Uint16(packet[offset+2:offset+4]) == 0x0800 && packet[offset+4] == 6 && packet[offset+5] == 4 {
			if len(packet) < offset+28 {
				return result, MembershipPacketHeaders
			}
			result.macs = appendObservableMAC(result.macs, packet[offset+8:offset+14])
			result.macs = appendObservableMAC(result.macs, packet[offset+18:offset+24])
			result.ips = appendObservableIP(result.ips, netip.AddrFrom4([4]byte(packet[offset+14:offset+18])))
			result.ips = appendObservableIP(result.ips, netip.AddrFrom4([4]byte(packet[offset+24:offset+28])))
		}
	}
	return result, ""
}

func ipIdentities(packet []byte) (identities, MembershipState) {
	var result identities
	if len(packet) == 0 {
		return result, MembershipPacketHeaders
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 || int(packet[0]&0x0f)*4 < 20 || len(packet) < int(packet[0]&0x0f)*4 {
			return result, MembershipPacketHeaders
		}
		result.ips = appendObservableIP(result.ips, netip.AddrFrom4([4]byte(packet[12:16])))
		result.ips = appendObservableIP(result.ips, netip.AddrFrom4([4]byte(packet[16:20])))
	case 6:
		if len(packet) < 40 {
			return result, MembershipPacketHeaders
		}
		result.ips = appendObservableIP(result.ips, netip.AddrFrom16([16]byte(packet[8:24])))
		result.ips = appendObservableIP(result.ips, netip.AddrFrom16([16]byte(packet[24:40])))
	default:
		return result, MembershipPacketHeaders
	}
	return result, ""
}

func appendObservableMAC(values []string, bytes []byte) []string {
	value := canonicalMACBytes(bytes)
	if value == "" {
		return values
	}
	return append(values, value)
}

func canonicalMAC(value string) string {
	if len(value) != 17 || value != strings.ToLower(value) {
		return ""
	}
	decoded := make([]byte, 6)
	for index := range decoded {
		part := value[index*3 : index*3+2]
		var parsed byte
		for _, char := range []byte(part) {
			parsed <<= 4
			switch {
			case char >= '0' && char <= '9':
				parsed += char - '0'
			case char >= 'a' && char <= 'f':
				parsed += char - 'a' + 10
			default:
				return ""
			}
		}
		decoded[index] = parsed
		if index < 5 && value[index*3+2] != ':' {
			return ""
		}
	}
	return canonicalMACBytes(decoded)
}

func canonicalMACBytes(value []byte) string {
	if len(value) != 6 || value[0]&1 != 0 {
		return ""
	}
	allZero := true
	for _, octet := range value {
		allZero = allZero && octet == 0
	}
	if allZero {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", value[0], value[1], value[2], value[3], value[4], value[5])
}

func appendObservableIP(values []string, address netip.Addr) []string {
	if !observableIP(address) {
		return values
	}
	return append(values, address.Unmap().String())
}

func observableIP(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsValid() && !address.IsUnspecified() && !address.IsMulticast() && address.String() != "255.255.255.255"
}

func validObservableIPString(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Unmap().String() == value && observableIP(address)
}

func sortedUnique(values []string) bool {
	for index, value := range values {
		if value == "" || index > 0 && value <= values[index-1] {
			return false
		}
	}
	return true
}
