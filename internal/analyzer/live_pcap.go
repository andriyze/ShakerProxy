package analyzer

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/bits"
	"time"
)

// Live analysis feeds Zeek one continuous packet stream across capture
// segments. dumpcap writes each segment as its own pcapng section, and
// libpcap stops reading a stream at the second section header, so the feed
// is converted to classic pcap: one file header, then a record per packet.

const (
	pcapngSectionHeader   = 0x0A0D0D0A
	pcapngByteOrderMagic  = 0x1A2B3C4D
	pcapngInterface       = 1
	pcapngObsoletePacket  = 2
	pcapngEnhancedPacket  = 6
	pcapngMaxBlockBytes   = 16 << 20
	pcapMagicMicroseconds = 0xA1B2C3D4
	pcapSnapLength        = 262144
	pcapLinkTypeEthernet  = 1
	// pcapLinkTypeRaw is raw IP with no link header, as dumpcap records a
	// WireGuard interface.
	pcapLinkTypeRaw = 101
)

var errLiveLinkTypeChanged = errors.New("capture link-layer type changed within the live stream")

type pcapInterface struct {
	linkType uint16
	// unitsPerSecond is the timestamp resolution (if_tsresol), 10^6 unless the
	// interface says otherwise.
	unitsPerSecond uint64
	offsetSeconds  int64
}

// pcapngToPcap converts pcapng blocks, fed in arbitrary chunks as a growing
// file is read, into classic pcap. It keeps an incomplete trailing block until
// the rest arrives.
type pcapngToPcap struct {
	pending    []byte
	order      binary.ByteOrder
	interfaces []pcapInterface
	linkType   int32 // -1 until the first interface is seen
	wroteHead  bool
	// last is the newest packet or tick time written; ticks never move
	// Zeek's clock backwards. lastPacket counts packets only.
	last       time.Time
	lastPacket time.Time
	Packets    uint64
}

func newPcapngToPcap() *pcapngToPcap {
	return &pcapngToPcap{linkType: -1}
}

// Feed consumes bytes of one segment and writes complete packets to out. A
// segment starts with a section header, which resets the interface list.
func (c *pcapngToPcap) Feed(data []byte, out io.Writer) error {
	c.pending = append(c.pending, data...)
	for {
		if len(c.pending) < 12 {
			return nil
		}
		blockType := binary.LittleEndian.Uint32(c.pending[:4])
		if blockType == pcapngSectionHeader {
			switch binary.LittleEndian.Uint32(c.pending[8:12]) {
			case pcapngByteOrderMagic:
				c.order = binary.LittleEndian
			default:
				if binary.BigEndian.Uint32(c.pending[8:12]) != pcapngByteOrderMagic {
					return errors.New("capture segment has an invalid pcapng section header")
				}
				c.order = binary.BigEndian
			}
			c.interfaces = nil
		}
		if c.order == nil {
			return errors.New("capture segment does not start with a pcapng section header")
		}
		blockType = c.order.Uint32(c.pending[:4])
		length := c.order.Uint32(c.pending[4:8])
		if length < 12 || length%4 != 0 || length > pcapngMaxBlockBytes {
			return errors.New("capture segment has an invalid pcapng block length")
		}
		if uint32(len(c.pending)) < length {
			return nil
		}
		block := c.pending[:length]
		if c.order.Uint32(block[length-4:]) != length {
			return errors.New("capture segment has a mismatched pcapng block length")
		}
		if err := c.block(blockType, block[8:length-4], out); err != nil {
			return err
		}
		c.pending = c.pending[length:]
	}
}

// Pending reports bytes of an incomplete block still waiting for more data.
func (c *pcapngToPcap) Pending() int { return len(c.pending) }

// Reset drops an incomplete block, for example when a segment ends early.
func (c *pcapngToPcap) Reset() { c.pending = nil }

func (c *pcapngToPcap) block(blockType uint32, body []byte, out io.Writer) error {
	switch blockType {
	case pcapngInterface:
		if len(body) < 8 {
			return errors.New("capture segment has a short interface block")
		}
		iface := pcapInterface{linkType: c.order.Uint16(body[:2]), unitsPerSecond: 1_000_000}
		options := body[8:]
		for len(options) >= 4 {
			code, size := c.order.Uint16(options[:2]), int(c.order.Uint16(options[2:4]))
			if code == 0 || 4+size > len(options) {
				break
			}
			value := options[4 : 4+size]
			switch {
			case code == 9 && size == 1:
				resolution := value[0]
				if resolution&0x80 == 0 {
					if resolution > 19 {
						return errors.New("capture segment has an unsupported timestamp resolution")
					}
					iface.unitsPerSecond = uint64(math.Pow10(int(resolution)))
				} else {
					if resolution&0x7f > 63 {
						return errors.New("capture segment has an unsupported timestamp resolution")
					}
					iface.unitsPerSecond = 1 << (resolution & 0x7f)
				}
			case code == 14 && size == 8:
				iface.offsetSeconds = int64(c.order.Uint64(value))
			}
			options = options[4+(size+3)&^3:]
		}
		if c.linkType >= 0 && int32(iface.linkType) != c.linkType {
			return errLiveLinkTypeChanged
		}
		c.linkType = int32(iface.linkType)
		if len(c.interfaces) >= 64 {
			return errors.New("capture segment declares too many interfaces")
		}
		c.interfaces = append(c.interfaces, iface)
		return nil
	case pcapngEnhancedPacket, pcapngObsoletePacket:
		if len(body) < 20 {
			return errors.New("capture segment has a short packet block")
		}
		var interfaceID uint32
		if blockType == pcapngEnhancedPacket {
			interfaceID = c.order.Uint32(body[:4])
		} else {
			interfaceID = uint32(c.order.Uint16(body[:2]))
		}
		if int(interfaceID) >= len(c.interfaces) {
			return errors.New("capture segment packet names an unknown interface")
		}
		iface := c.interfaces[interfaceID]
		units := uint64(c.order.Uint32(body[4:8]))<<32 | uint64(c.order.Uint32(body[8:12]))
		captured, original := c.order.Uint32(body[12:16]), c.order.Uint32(body[16:20])
		if uint64(captured) > uint64(len(body)-20) || captured > pcapSnapLength {
			return errors.New("capture segment packet is longer than its block")
		}
		seconds := int64(units/iface.unitsPerSecond) + iface.offsetSeconds
		high, low := bits.Mul64(units%iface.unitsPerSecond, 1_000_000)
		micros, _ := bits.Div64(high, low, iface.unitsPerSecond)
		if seconds < 0 || seconds > math.MaxUint32 {
			return errors.New("capture segment packet time is out of range")
		}
		if err := c.writeHeader(out); err != nil {
			return err
		}
		if err := writePcapRecord(out, seconds, int64(micros), body[20:20+captured], original); err != nil {
			return err
		}
		stamp := time.Unix(seconds, int64(micros)*1000)
		if stamp.After(c.last) {
			c.last = stamp
		}
		if stamp.After(c.lastPacket) {
			c.lastPacket = stamp
		}
		c.Packets++
		return nil
	default:
		// Statistics, name resolution and custom blocks carry no packets.
		return nil
	}
}

// Tick writes a frame Zeek parses and ignores, stamped at, so Zeek's clock
// keeps moving while the capture is quiet. Reading a trace, Zeek's clock
// advances only with packets: without ticks, connection timeouts and the
// records they write wait for the next packet. On Ethernet the frame uses
// the IEEE local experimental EtherType; on raw IP (the VPN) it is a
// loopback IPv4 packet of experimental protocol 253 (RFC 3692). No Zeek
// analyzer claims either. Other link types get no ticks. It reports whether
// a tick was written.
func (c *pcapngToPcap) Tick(at time.Time, out io.Writer) (bool, error) {
	if !c.wroteHead || !at.After(c.last) {
		return false, nil
	}
	var frame []byte
	switch c.linkType {
	case pcapLinkTypeEthernet:
		frame = make([]byte, 60)
		binary.BigEndian.PutUint16(frame[12:14], 0x88B5)
	case pcapLinkTypeRaw:
		frame = rawTickPacket()
	default:
		return false, nil
	}
	micros := at.Nanosecond() / 1000
	if err := writePcapRecord(out, at.Unix(), int64(micros), frame, uint32(len(frame))); err != nil {
		return false, err
	}
	c.last = at
	return true, nil
}

// rawTickPacket is a 20-byte IPv4 header, 127.0.0.1 to 127.0.0.1, protocol
// 253, with a valid checksum.
func rawTickPacket() []byte {
	packet := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1}
	var sum uint32
	for index := 0; index < len(packet); index += 2 {
		sum += uint32(packet[index])<<8 | uint32(packet[index+1])
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	return packet
}

func writePcapRecord(out io.Writer, seconds, micros int64, data []byte, original uint32) error {
	record := make([]byte, 16, 16+len(data))
	binary.LittleEndian.PutUint32(record[0:4], uint32(seconds))
	binary.LittleEndian.PutUint32(record[4:8], uint32(micros))
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(record[12:16], original)
	_, err := out.Write(append(record, data...))
	return err
}

func (c *pcapngToPcap) writeHeader(out io.Writer) error {
	if c.wroteHead {
		return nil
	}
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], pcapMagicMicroseconds)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], pcapSnapLength)
	binary.LittleEndian.PutUint32(header[20:24], uint32(c.linkType))
	if _, err := out.Write(header); err != nil {
		return err
	}
	c.wroteHead = true
	return nil
}
