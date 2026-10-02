package wifi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MAC is an 802.11 address.
type MAC [6]byte

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// Group reports a broadcast or multicast address.
func (m MAC) Group() bool { return m[0]&0x01 != 0 }

// Randomized reports a locally administered unicast address, which is what
// phones and laptops use for private (randomized) Wi-Fi addresses.
func (m MAC) Randomized() bool { return m[0]&0x02 != 0 && !m.Group() }

// Zero reports the all-zero address.
func (m MAC) Zero() bool { return m == MAC{} }

// ParseMAC reads "aa:bb:cc:dd:ee:ff" (or with dashes), in any case.
func ParseMAC(value string) (MAC, bool) {
	var mac MAC
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 17 {
		return mac, false
	}
	for index := 0; index < 6; index++ {
		if index > 0 && value[index*3-1] != ':' && value[index*3-1] != '-' {
			return mac, false
		}
		high, okHigh := hexValue(value[index*3])
		low, okLow := hexValue(value[index*3+1])
		if !okHigh || !okLow {
			return mac, false
		}
		mac[index] = high<<4 | low
	}
	return mac, true
}

func hexValue(char byte) (byte, bool) {
	switch {
	case char >= '0' && char <= '9':
		return char - '0', true
	case char >= 'a' && char <= 'f':
		return char - 'a' + 10, true
	}
	return 0, false
}

// 802.11 management frame subtypes.
const (
	SubtypeAssocRequest     = 0
	SubtypeAssocResponse    = 1
	SubtypeReassocRequest   = 2
	SubtypeReassocResponse  = 3
	SubtypeProbeRequest     = 4
	SubtypeProbeResponse    = 5
	SubtypeBeacon           = 8
	SubtypeDisassociation   = 10
	SubtypeAuthentication   = 11
	SubtypeDeauthentication = 12
	SubtypeAction           = 13
)

// Element IDs ShakerProxy reads.
const (
	ElementSSID           = 0
	ElementSupportedRates = 1
	ElementDSParameter    = 3
	ElementHTCapabilities = 45
	ElementRSN            = 48
	ElementExtendedRates  = 50
	ElementExtCapability  = 127
	ElementVHTCapability  = 191
	ElementVendor         = 221
	ElementExtension      = 255
)

// MaxSSIDBytes is the longest SSID 802.11 allows.
const MaxSSIDBytes = 32

// ErrNotManagement is returned for control and data frames.
var ErrNotManagement = errors.New("not an 802.11 management frame")

var errFrame = errors.New("802.11 frame is invalid")

// Element is one information element of a management frame body.
type Element struct {
	ID   uint8
	Data []byte
}

// Management is one parsed 802.11 management frame. Its byte slices point
// into the captured packet.
type Management struct {
	Subtype   uint8
	Retry     bool
	Protected bool
	// Addr1 is the receiver, Addr2 the transmitter, Addr3 the BSSID.
	Addr1, Addr2, Addr3 MAC
	Sequence            uint16

	Capability    uint16
	StatusCode    uint16
	HasStatus     bool
	ReasonCode    uint16
	HasReason     bool
	AuthAlgorithm uint16
	AuthSequence  uint16
	CurrentAP     MAC
	HasCurrentAP  bool
	Elements      []Element
	// ElementsTruncated reports a body whose last element ran past its end.
	ElementsTruncated bool
}

// ParseManagement parses an 802.11 frame (without radiotap). fcs strips a
// trailing frame check sequence.
func ParseManagement(data []byte, fcs bool) (Management, error) {
	if fcs {
		if len(data) < 4 {
			return Management{}, errFrame
		}
		data = data[:len(data)-4]
	}
	if len(data) < 24 {
		if len(data) >= 2 && (binary.LittleEndian.Uint16(data[0:2])>>2)&0x3 != 0 {
			return Management{}, ErrNotManagement
		}
		return Management{}, errFrame
	}
	control := binary.LittleEndian.Uint16(data[0:2])
	if control&0x3 != 0 {
		return Management{}, errFrame
	}
	if (control>>2)&0x3 != 0 {
		return Management{}, ErrNotManagement
	}
	flags := byte(control >> 8)
	frame := Management{
		Subtype:   uint8(control>>4) & 0xf,
		Retry:     flags&0x08 != 0,
		Protected: flags&0x40 != 0,
		Sequence:  binary.LittleEndian.Uint16(data[22:24]) >> 4,
	}
	copy(frame.Addr1[:], data[4:10])
	copy(frame.Addr2[:], data[10:16])
	copy(frame.Addr3[:], data[16:22])
	headerLength := 24
	if flags&0x80 != 0 {
		// +HTC: a management frame with the Order bit carries HT Control.
		headerLength = 28
	}
	if len(data) < headerLength {
		return Management{}, errFrame
	}
	body := data[headerLength:]
	if frame.Protected {
		// Management frame protection encrypted the body (deauthentication,
		// disassociation and robust action frames): nothing in it is
		// readable.
		return frame, nil
	}
	fixed := 0
	switch frame.Subtype {
	case SubtypeAssocRequest:
		if len(body) < 4 {
			return Management{}, errFrame
		}
		frame.Capability = binary.LittleEndian.Uint16(body[0:2])
		fixed = 4
	case SubtypeReassocRequest:
		if len(body) < 10 {
			return Management{}, errFrame
		}
		frame.Capability = binary.LittleEndian.Uint16(body[0:2])
		copy(frame.CurrentAP[:], body[4:10])
		frame.HasCurrentAP = !frame.CurrentAP.Zero()
		fixed = 10
	case SubtypeAssocResponse, SubtypeReassocResponse:
		if len(body) < 6 {
			return Management{}, errFrame
		}
		frame.Capability = binary.LittleEndian.Uint16(body[0:2])
		frame.StatusCode, frame.HasStatus = binary.LittleEndian.Uint16(body[2:4]), true
		fixed = 6
	case SubtypeProbeRequest:
		fixed = 0
	case SubtypeProbeResponse, SubtypeBeacon:
		if len(body) < 12 {
			return Management{}, errFrame
		}
		frame.Capability = binary.LittleEndian.Uint16(body[10:12])
		fixed = 12
	case SubtypeDisassociation, SubtypeDeauthentication:
		if len(body) < 2 {
			return Management{}, errFrame
		}
		frame.ReasonCode, frame.HasReason = binary.LittleEndian.Uint16(body[0:2]), true
		fixed = 2
	case SubtypeAuthentication:
		if len(body) < 6 {
			return Management{}, errFrame
		}
		frame.AuthAlgorithm = binary.LittleEndian.Uint16(body[0:2])
		frame.AuthSequence = binary.LittleEndian.Uint16(body[2:4])
		frame.StatusCode, frame.HasStatus = binary.LittleEndian.Uint16(body[4:6]), true
		// SAE and FILS bodies are not element lists.
		if frame.AuthAlgorithm != 0 && frame.AuthAlgorithm != 1 {
			return frame, nil
		}
		fixed = 6
	default:
		return frame, nil
	}
	frame.Elements, frame.ElementsTruncated = parseElements(body[fixed:])
	return frame, nil
}

const maxElements = 128

func parseElements(data []byte) ([]Element, bool) {
	elements := make([]Element, 0, 16)
	for len(data) > 0 {
		if len(data) < 2 || len(elements) >= maxElements {
			return elements, true
		}
		length := int(data[1])
		if 2+length > len(data) {
			return elements, true
		}
		elements = append(elements, Element{ID: data[0], Data: data[2 : 2+length]})
		data = data[2+length:]
	}
	return elements, false
}

// Element returns the first element with the ID.
func (m Management) Element(id uint8) ([]byte, bool) {
	for _, element := range m.Elements {
		if element.ID == id {
			return element.Data, true
		}
	}
	return nil, false
}

// SSID is a network name as seen in a frame. Wildcard is the empty SSID of
// a probe for any network; Hidden a beacon that hides its name.
type SSID struct {
	Name     string
	Present  bool
	Wildcard bool
	Hidden   bool
}

// SSID returns the frame's network name, made safe to display: invalid
// UTF-8 and control characters are written as \xNN.
func (m Management) SSID() SSID {
	raw, ok := m.Element(ElementSSID)
	if !ok || len(raw) > MaxSSIDBytes {
		return SSID{}
	}
	if len(raw) == 0 {
		return SSID{Present: true, Wildcard: true, Hidden: true}
	}
	allZero := true
	for _, value := range raw {
		if value != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return SSID{Present: true, Hidden: true}
	}
	return SSID{Name: DisplaySSID(raw), Present: true}
}

// DisplaySSID renders raw SSID bytes as text.
func DisplaySSID(raw []byte) string {
	var builder strings.Builder
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		if r == utf8.RuneError && size <= 1 || !unicode.IsPrint(r) || r == '\\' {
			if r == '\\' {
				builder.WriteString(`\\`)
			} else {
				for _, value := range raw[:max(size, 1)] {
					fmt.Fprintf(&builder, `\x%02x`, value)
				}
			}
			raw = raw[max(size, 1):]
			continue
		}
		builder.WriteRune(r)
		raw = raw[size:]
	}
	return builder.String()
}

// Channel is the channel the DS Parameter Set element names, 0 if absent.
func (m Management) Channel() int {
	value, ok := m.Element(ElementDSParameter)
	if !ok || len(value) != 1 {
		return 0
	}
	return int(value[0])
}

// TransmitterIsBSSID reports a frame the access point sent.
func (m Management) TransmitterIsBSSID() bool { return m.Addr2 == m.Addr3 }
