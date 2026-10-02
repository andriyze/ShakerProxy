package pcapng

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"time"
)

// TCPFlowKey identifies one TCP connection by its endpoints. Client is the
// side that opened it, usually the lab device; packets in both directions
// match.
type TCPFlowKey struct {
	Client netip.AddrPort
	Server netip.AddrPort
}

// TCPSegment is one captured TCP packet of a connection.
type TCPSegment struct {
	At         time.Time
	FromClient bool
	Seq        uint32
	SYN        bool
	FIN        bool
	RST        bool
	Payload    []byte
	// Cut reports a payload shortened by the capture's snap length.
	Cut bool
}

type TCPFlowLimits struct {
	MaxPackets      int
	MaxPayloadBytes int
}

// TCPFlowScan accumulates the packets of one connection across capture files.
type TCPFlowScan struct {
	Segments     []TCPSegment
	PacketsRead  uint64
	PayloadBytes int
	LimitReached bool
}

// ScanTCPFlow reads one PCAPNG file and appends the packets of the connection
// observed in [startAt, endAt) to scan. Packets without a timestamp (simple
// packet blocks) are kept. Reading stops quietly once a limit is reached.
func ScanTCPFlow(ctx context.Context, reader io.Reader, key TCPFlowKey, startAt, endAt time.Time, limits TCPFlowLimits, scan *TCPFlowScan) error {
	if ctx == nil || reader == nil || scan == nil {
		return errors.New("PCAPNG flow scan is incomplete")
	}
	if !key.Client.IsValid() || !key.Server.IsValid() || key.Client.Port() == 0 || key.Server.Port() == 0 {
		return errors.New("PCAPNG flow endpoints are invalid")
	}
	if limits.MaxPackets < 1 || limits.MaxPayloadBytes < 1 {
		return errors.New("PCAPNG flow limits are invalid")
	}
	client := netip.AddrPortFrom(key.Client.Addr().Unmap(), key.Client.Port())
	server := netip.AddrPortFrom(key.Server.Addr().Unmap(), key.Server.Port())
	var section *rewriteSection
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if scan.LimitReached {
			return nil
		}
		block, blockType, order, err := readBlock(reader, rewriteReadSection(section))
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
			section = &rewriteSection{order: order}
			continue
		}
		if section == nil {
			return fmt.Errorf("%w: data precedes the section header", ErrInvalidPCAPNG)
		}
		if blockType == 1 {
			configuration, err := parseRewriteInterface(block, section.order)
			if err != nil || len(section.interfaces) >= maxInterfaces {
				return fmt.Errorf("%w: interface block is invalid", ErrInvalidPCAPNG)
			}
			section.interfaces = append(section.interfaces, configuration)
			continue
		}
		packet, configuration, timestamp, packetBlock, err := rewritePacket(block, blockType, section)
		if err != nil {
			return err
		}
		if !packetBlock {
			continue
		}
		scan.PacketsRead++
		segment, ok := decodeTCP(configuration.linkType, packet)
		if !ok {
			continue
		}
		switch {
		case segment.source == client && segment.destination == server:
			segment.value.FromClient = true
		case segment.source == server && segment.destination == client:
		default:
			continue
		}
		if timestamp != nil {
			at, err := configuration.observedAt(*timestamp)
			if err != nil {
				return err
			}
			if at.Before(startAt) || !at.Before(endAt) {
				continue
			}
			segment.value.At = at
		}
		if len(scan.Segments) >= limits.MaxPackets || scan.PayloadBytes+len(segment.value.Payload) > limits.MaxPayloadBytes {
			scan.LimitReached = true
			return nil
		}
		segment.value.Payload = append([]byte(nil), segment.value.Payload...)
		scan.PayloadBytes += len(segment.value.Payload)
		scan.Segments = append(scan.Segments, segment.value)
	}
}

type decodedTCP struct {
	source      netip.AddrPort
	destination netip.AddrPort
	value       TCPSegment
}

func decodeTCP(linkType uint16, packet []byte) (decodedTCP, bool) {
	switch linkType {
	case 1:
		if len(packet) < 14 {
			return decodedTCP{}, false
		}
		etherType := binary.BigEndian.Uint16(packet[12:14])
		offset := 14
		for tags := 0; tags < 4 && (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100); tags++ {
			if len(packet) < offset+4 {
				return decodedTCP{}, false
			}
			etherType = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			offset += 4
		}
		if etherType != 0x0800 && etherType != 0x86dd {
			return decodedTCP{}, false
		}
		return decodeIPTCP(packet[offset:])
	case 101:
		return decodeIPTCP(packet)
	default:
		return decodedTCP{}, false
	}
}

func decodeIPTCP(packet []byte) (decodedTCP, bool) {
	if len(packet) == 0 {
		return decodedTCP{}, false
	}
	var source, destination netip.Addr
	var transport []byte
	// declared is how long the TCP segment was on the wire; a shorter
	// capture means the snap length cut it.
	var declared int
	switch packet[0] >> 4 {
	case 4:
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || len(packet) < headerLength {
			return decodedTCP{}, false
		}
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		fragment := binary.BigEndian.Uint16(packet[6:8])
		if packet[9] != 6 || total < headerLength || fragment&0x3fff != 0 {
			return decodedTCP{}, false
		}
		source = netip.AddrFrom4([4]byte(packet[12:16]))
		destination = netip.AddrFrom4([4]byte(packet[16:20]))
		declared = total - headerLength
		transport = packet[headerLength:min(len(packet), total)]
	case 6:
		if len(packet) < 40 {
			return decodedTCP{}, false
		}
		source = netip.AddrFrom16([16]byte(packet[8:24])).Unmap()
		destination = netip.AddrFrom16([16]byte(packet[24:40])).Unmap()
		next := packet[6]
		payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
		offset := 40
		// Hop-by-hop, routing and destination options; a fragment header
		// (44) or anything else ends the walk.
		for extensions := 0; extensions < 4 && (next == 0 || next == 43 || next == 60); extensions++ {
			if len(packet) < offset+2 {
				return decodedTCP{}, false
			}
			next = packet[offset]
			offset += (int(packet[offset+1]) + 1) * 8
		}
		if next != 6 || len(packet) < offset || offset-40 > payloadLength {
			return decodedTCP{}, false
		}
		declared = payloadLength - (offset - 40)
		transport = packet[offset:min(len(packet), 40+payloadLength)]
	default:
		return decodedTCP{}, false
	}
	if len(transport) < 20 {
		return decodedTCP{}, false
	}
	dataOffset := int(transport[12]>>4) * 4
	if dataOffset < 20 || len(transport) < dataOffset || declared < dataOffset {
		return decodedTCP{}, false
	}
	flags := transport[13]
	result := decodedTCP{
		source:      netip.AddrPortFrom(source, binary.BigEndian.Uint16(transport[0:2])),
		destination: netip.AddrPortFrom(destination, binary.BigEndian.Uint16(transport[2:4])),
		value: TCPSegment{
			Seq:     binary.BigEndian.Uint32(transport[4:8]),
			FIN:     flags&0x01 != 0,
			SYN:     flags&0x02 != 0,
			RST:     flags&0x04 != 0,
			Payload: transport[dataOffset:],
			Cut:     len(transport) < declared,
		},
	}
	return result, true
}

// TCPStream is one direction of a connection, reassembled in sequence order.
type TCPStream struct {
	Data []byte
	// Gap reports data missing from the recording at GapAt bytes into the
	// stream; nothing after it is included.
	Gap   bool
	GapAt int
	// Truncated reports a stream longer than the reassembly bound.
	Truncated bool
	// Cut reports payloads shortened by the capture's snap length.
	Cut bool
	// FromStart reports that the recording includes the connection's SYN,
	// so the stream begins at its first byte.
	FromStart bool
	FIN       bool
}

// ReassembleTCP rebuilds one direction of a connection from its segments.
// Retransmitted and overlapping data keep the first copy; data before the
// first byte the recording saw (a connection that started earlier) is
// dropped. 32-bit sequence wraparound is handled relative to the base.
func ReassembleTCP(segments []TCPSegment, fromClient bool, maxBytes int) TCPStream {
	var stream TCPStream
	var base uint32
	baseKnown := false
	var first uint32
	firstKnown := false
	for _, segment := range segments {
		if segment.FromClient != fromClient {
			continue
		}
		stream.Cut = stream.Cut || segment.Cut
		stream.FIN = stream.FIN || segment.FIN
		if segment.SYN && !baseKnown {
			base, baseKnown = segment.Seq+1, true
			stream.FromStart = true
		}
		if len(segment.Payload) > 0 && !firstKnown {
			first, firstKnown = segment.Seq, true
		}
	}
	if !baseKnown {
		if !firstKnown {
			return stream
		}
		// Without the SYN, the stream starts at the lowest sequence number
		// seen, measured relative to the first data segment.
		lowest := int64(0)
		for _, segment := range segments {
			if segment.FromClient == fromClient && len(segment.Payload) > 0 {
				lowest = min(lowest, int64(int32(segment.Seq-first)))
			}
		}
		base = first + uint32(int32(lowest))
	}
	type piece struct {
		offset int64
		data   []byte
	}
	pieces := make([]piece, 0, len(segments))
	for _, segment := range segments {
		if segment.FromClient != fromClient || len(segment.Payload) == 0 {
			continue
		}
		offset := int64(int32(segment.Seq - base))
		data := segment.Payload
		if offset < 0 {
			if -offset >= int64(len(data)) {
				continue
			}
			data = data[-offset:]
			offset = 0
		}
		pieces = append(pieces, piece{offset: offset, data: data})
	}
	sort.SliceStable(pieces, func(i, j int) bool { return pieces[i].offset < pieces[j].offset })
	cursor := int64(0)
	for _, item := range pieces {
		end := item.offset + int64(len(item.data))
		if end <= cursor {
			continue
		}
		if item.offset > cursor {
			stream.Gap, stream.GapAt = true, int(cursor)
			break
		}
		data := item.data[cursor-item.offset:]
		if room := int64(maxBytes) - int64(len(stream.Data)); int64(len(data)) > room {
			stream.Data = append(stream.Data, data[:room]...)
			stream.Truncated = true
			break
		}
		stream.Data = append(stream.Data, data...)
		cursor = end
	}
	return stream
}
