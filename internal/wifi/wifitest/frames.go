// Package wifitest builds 802.11 management frames with radiotap headers,
// as a Linux monitor interface captures them, for tests.
package wifitest

import (
	"encoding/binary"
)

// Radio describes the radiotap header: channel frequency, signal and
// whether the frame carries a frame check sequence.
type Radio struct {
	FrequencyMHz int
	SignalDBM    int
	FCS          bool
	BadFCS       bool
	// TSFT adds the 8-byte timestamp field, which shifts and aligns the
	// fields after it.
	TSFT bool
}

// Radiotap returns a radiotap header with flags, rate, channel and signal.
func Radiotap(radio Radio) []byte {
	present := uint32(1<<1 | 1<<2 | 1<<3 | 1<<5)
	header := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	if radio.TSFT {
		present |= 1
		header = append(header, make([]byte, 8)...)
		binary.LittleEndian.PutUint64(header[8:16], 123456789)
	}
	flags := byte(0)
	if radio.FCS {
		flags |= 0x10
	}
	if radio.BadFCS {
		flags |= 0x40
	}
	header = append(header, flags, 12) // flags, rate (6 Mb/s)
	channel := make([]byte, 4)
	binary.LittleEndian.PutUint16(channel[0:2], uint16(radio.FrequencyMHz))
	binary.LittleEndian.PutUint16(channel[2:4], 0x00a0)
	header = append(header, channel...)
	header = append(header, byte(int8(radio.SignalDBM)))
	binary.LittleEndian.PutUint32(header[4:8], present)
	binary.LittleEndian.PutUint16(header[2:4], uint16(len(header)))
	return header
}

// MAC parses "aa:bb:cc:dd:ee:ff"; it panics on bad input (tests only).
func MAC(value string) [6]byte {
	var mac [6]byte
	for index := 0; index < 6; index++ {
		mac[index] = nibble(value[index*3])<<4 | nibble(value[index*3+1])
	}
	return mac
}

func nibble(char byte) byte {
	switch {
	case char >= '0' && char <= '9':
		return char - '0'
	case char >= 'a' && char <= 'f':
		return char - 'a' + 10
	case char >= 'A' && char <= 'F':
		return char - 'A' + 10
	}
	panic("bad hex digit")
}

// Header is a management frame header.
type Header struct {
	Subtype   uint8
	Addr1     string
	Addr2     string
	Addr3     string
	Sequence  uint16
	Protected bool
	Retry     bool
}

func header(h Header) []byte {
	frame := make([]byte, 24)
	control := uint16(h.Subtype) << 4
	if h.Retry {
		control |= 0x08 << 8
	}
	if h.Protected {
		control |= 0x40 << 8
	}
	binary.LittleEndian.PutUint16(frame[0:2], control)
	for index, address := range []string{h.Addr1, h.Addr2, h.Addr3} {
		mac := MAC(address)
		copy(frame[4+6*index:10+6*index], mac[:])
	}
	binary.LittleEndian.PutUint16(frame[22:24], h.Sequence<<4)
	return frame
}

// Element encodes one information element.
func Element(id byte, data []byte) []byte {
	return append([]byte{id, byte(len(data))}, data...)
}

// SSID encodes an SSID element.
func SSID(name string) []byte { return Element(0, []byte(name)) }

// DSParameter encodes the channel element.
func DSParameter(channel int) []byte { return Element(3, []byte{byte(channel)}) }

// ProbeElements are typical phone probe request elements after the SSID.
func ProbeElements() []byte {
	elements := Element(1, []byte{0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24})
	elements = append(elements, Element(50, []byte{0x30, 0x48, 0x60, 0x6c})...)
	elements = append(elements, Element(45, []byte{0xef, 0x09, 0x1b, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})...)
	elements = append(elements, Element(127, []byte{0x04, 0x00, 0x0a, 0x82, 0x01, 0x40, 0x00, 0x40, 0x80})...)
	return append(elements, Element(221, []byte{0x00, 0x50, 0xf2, 0x08, 0x00, 0x10, 0x00})...)
}

// OtherProbeElements are a different device model's probe elements.
func OtherProbeElements() []byte {
	elements := Element(1, []byte{0x02, 0x04, 0x0b, 0x16})
	return append(elements, Element(45, []byte{0x2c, 0x01, 0x1b, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})...)
}

// RSN returns an RSN element with the given AKM suite types and
// capabilities (0x0080 MFP capable, 0x00c0 required).
func RSN(capabilities uint16, akms ...byte) []byte {
	data := []byte{1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4}
	count := make([]byte, 2)
	binary.LittleEndian.PutUint16(count, uint16(len(akms)))
	data = append(data, count...)
	for _, akm := range akms {
		data = append(data, 0x00, 0x0f, 0xac, akm)
	}
	caps := make([]byte, 2)
	binary.LittleEndian.PutUint16(caps, capabilities)
	return Element(48, append(data, caps...))
}

// Management returns radiotap + header + body (+ FCS when the radio says
// so).
func Management(radio Radio, h Header, body []byte) []byte {
	frame := append(header(h), body...)
	if radio.FCS {
		frame = append(frame, 0xde, 0xad, 0xbe, 0xef)
	}
	return append(Radiotap(radio), frame...)
}

// ProbeRequest from client for ssid ("" for any network).
func ProbeRequest(radio Radio, client, ssid string, sequence uint16) []byte {
	body := append(SSID(ssid), ProbeElements()...)
	return Management(radio, Header{Subtype: 4, Addr1: "ff:ff:ff:ff:ff:ff", Addr2: client, Addr3: "ff:ff:ff:ff:ff:ff", Sequence: sequence}, body)
}

// ProbeRequestWith sends custom elements after the SSID.
func ProbeRequestWith(radio Radio, client, ssid string, sequence uint16, elements []byte) []byte {
	body := append(SSID(ssid), elements...)
	return Management(radio, Header{Subtype: 4, Addr1: "ff:ff:ff:ff:ff:ff", Addr2: client, Addr3: "ff:ff:ff:ff:ff:ff", Sequence: sequence}, body)
}

// Beacon from bssid for ssid with the given security elements.
func Beacon(radio Radio, bssid, ssid string, channel int, capability uint16, security []byte) []byte {
	fixed := make([]byte, 12)
	binary.LittleEndian.PutUint16(fixed[8:10], 100)
	binary.LittleEndian.PutUint16(fixed[10:12], capability)
	body := append(fixed, SSID(ssid)...)
	body = append(body, DSParameter(channel)...)
	body = append(body, security...)
	return Management(radio, Header{Subtype: 8, Addr1: "ff:ff:ff:ff:ff:ff", Addr2: bssid, Addr3: bssid}, body)
}

// Authentication between client and bssid; fromAP selects the direction.
func Authentication(radio Radio, client, bssid string, fromAP bool, algorithm, sequence, status uint16) []byte {
	body := make([]byte, 6)
	binary.LittleEndian.PutUint16(body[0:2], algorithm)
	binary.LittleEndian.PutUint16(body[2:4], sequence)
	binary.LittleEndian.PutUint16(body[4:6], status)
	h := Header{Subtype: 11, Addr1: bssid, Addr2: client, Addr3: bssid}
	if fromAP {
		h.Addr1, h.Addr2 = client, bssid
	}
	return Management(radio, h, body)
}

// AssociationRequest from client to bssid; a non-empty currentAP makes it a
// reassociation request.
func AssociationRequest(radio Radio, client, bssid, ssid, currentAP string, sequence uint16) []byte {
	subtype := uint8(0)
	body := []byte{0x31, 0x04, 0x0a, 0x00}
	if currentAP != "" {
		subtype = 2
		mac := MAC(currentAP)
		body = append(body, mac[:]...)
	}
	body = append(body, SSID(ssid)...)
	body = append(body, ProbeElements()...)
	return Management(radio, Header{Subtype: subtype, Addr1: bssid, Addr2: client, Addr3: bssid, Sequence: sequence}, body)
}

// AssociationResponse from bssid to client.
func AssociationResponse(radio Radio, client, bssid string, reassociation bool, status uint16) []byte {
	subtype := uint8(1)
	if reassociation {
		subtype = 3
	}
	body := make([]byte, 6)
	binary.LittleEndian.PutUint16(body[0:2], 0x0431)
	binary.LittleEndian.PutUint16(body[2:4], status)
	binary.LittleEndian.PutUint16(body[4:6], 0xc001)
	return Management(radio, Header{Subtype: subtype, Addr1: client, Addr2: bssid, Addr3: bssid}, body)
}

// Deauthentication (or disassociation) with a reason; fromAP selects the
// direction; protected encrypts the body as management frame protection
// does.
func Deauthentication(radio Radio, client, bssid string, fromAP, disassociation, protected bool, reason uint16) []byte {
	subtype := uint8(12)
	if disassociation {
		subtype = 10
	}
	body := make([]byte, 2)
	binary.LittleEndian.PutUint16(body, reason)
	if protected {
		body = []byte{1, 0, 0, 0x20, 0, 0, 0, 0, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a}
	}
	h := Header{Subtype: subtype, Addr1: bssid, Addr2: client, Addr3: bssid, Protected: protected}
	if fromAP {
		h.Addr1, h.Addr2 = client, bssid
	}
	return Management(radio, h, body)
}
