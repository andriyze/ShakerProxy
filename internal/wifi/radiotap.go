// Package wifi turns 802.11 management frames captured by a passive monitor
// interface into ShakerProxy events: which networks a device searches for,
// when it authenticates, associates, roams and disconnects, and which
// networks are around the lab. It never transmits; it only reads frames.
//
// Captured frames are hostile input: every parser here bounds its reads and
// rejects what it does not understand.
package wifi

import (
	"encoding/binary"
	"errors"
)

// LinkTypeRadiotap is DLT_IEEE802_11_RADIO: 802.11 frames with a radiotap
// header, what a Linux monitor interface captures.
const LinkTypeRadiotap = 127

// Radiotap is the part of a radiotap header ShakerProxy reads.
type Radiotap struct {
	// Length is the header length; the 802.11 frame follows it.
	Length int
	// FCS reports a 4-byte frame check sequence at the end of the frame;
	// BadFCS a frame the radio received damaged.
	FCS    bool
	BadFCS bool
	// FrequencyMHz is the channel the frame was received on, 0 if unknown.
	FrequencyMHz int
	// SignalDBM is the received signal strength when HasSignal is set.
	SignalDBM int
	HasSignal bool
}

const (
	radiotapTSFT      = 1 << 0
	radiotapFlags     = 1 << 1
	radiotapRate      = 1 << 2
	radiotapChannel   = 1 << 3
	radiotapFHSS      = 1 << 4
	radiotapDBMSignal = 1 << 5
	radiotapExtended  = 1 << 31

	radiotapFlagFCS    = 0x10
	radiotapFlagBadFCS = 0x40

	maxRadiotapPresentWords = 16
)

var errRadiotap = errors.New("radiotap header is invalid")

// ParseRadiotap reads the header at the start of a captured frame. Only the
// fields before any vendor or extended namespace are read: TSFT, flags,
// rate, channel, FHSS and the antenna signal, which keeps every offset
// computable from the standard field sizes and alignments.
func ParseRadiotap(data []byte) (Radiotap, error) {
	if len(data) < 8 || data[0] != 0 {
		return Radiotap{}, errRadiotap
	}
	length := int(binary.LittleEndian.Uint16(data[2:4]))
	if length < 8 || length > len(data) {
		return Radiotap{}, errRadiotap
	}
	header := data[:length]
	present := binary.LittleEndian.Uint32(header[4:8])
	offset := 8
	for word, words := present, 1; word&radiotapExtended != 0; words++ {
		if words >= maxRadiotapPresentWords || offset+4 > length {
			return Radiotap{}, errRadiotap
		}
		word = binary.LittleEndian.Uint32(header[offset : offset+4])
		offset += 4
	}
	result := Radiotap{Length: length}
	// Field data is aligned to its natural size, counted from the start of
	// the header.
	field := func(alignment, size int) ([]byte, bool) {
		offset = (offset + alignment - 1) &^ (alignment - 1)
		if offset+size > length {
			return nil, false
		}
		value := header[offset : offset+size]
		offset += size
		return value, true
	}
	if present&radiotapTSFT != 0 {
		if _, ok := field(8, 8); !ok {
			return Radiotap{}, errRadiotap
		}
	}
	if present&radiotapFlags != 0 {
		value, ok := field(1, 1)
		if !ok {
			return Radiotap{}, errRadiotap
		}
		result.FCS = value[0]&radiotapFlagFCS != 0
		result.BadFCS = value[0]&radiotapFlagBadFCS != 0
	}
	if present&radiotapRate != 0 {
		if _, ok := field(1, 1); !ok {
			return Radiotap{}, errRadiotap
		}
	}
	if present&radiotapChannel != 0 {
		value, ok := field(2, 4)
		if !ok {
			return Radiotap{}, errRadiotap
		}
		frequency := int(binary.LittleEndian.Uint16(value[0:2]))
		if ChannelForFrequency(frequency) != 0 {
			result.FrequencyMHz = frequency
		}
	}
	if present&radiotapFHSS != 0 {
		if _, ok := field(1, 2); !ok {
			return Radiotap{}, errRadiotap
		}
	}
	if present&radiotapDBMSignal != 0 {
		value, ok := field(1, 1)
		if !ok {
			return Radiotap{}, errRadiotap
		}
		signal := int(int8(value[0]))
		// A real received signal is negative; 0 and positive values are
		// drivers reporting nothing useful.
		if signal < 0 && signal > -120 {
			result.SignalDBM, result.HasSignal = signal, true
		}
	}
	return result, nil
}

// ChannelForFrequency returns the 802.11 channel number of a centre
// frequency in the 2.4, 5 or 6 GHz band, or 0.
func ChannelForFrequency(frequency int) int {
	switch {
	case frequency == 2484:
		return 14
	case frequency >= 2412 && frequency <= 2472 && (frequency-2407)%5 == 0:
		return (frequency - 2407) / 5
	case frequency >= 5160 && frequency <= 5885 && (frequency-5000)%5 == 0:
		return (frequency - 5000) / 5
	case frequency >= 5955 && frequency <= 7115 && (frequency-5950)%5 == 0:
		return (frequency - 5950) / 5
	}
	return 0
}

// FrequencyForChannel returns the centre frequency of a 2.4 or 5 GHz
// channel, or 0. 6 GHz channel numbers overlap 2.4 GHz ones, so they are
// not accepted here.
func FrequencyForChannel(channel int) int {
	switch {
	case channel == 14:
		return 2484
	case channel >= 1 && channel <= 13:
		return 2407 + 5*channel
	case channel >= 32 && channel <= 177:
		return 5000 + 5*channel
	}
	return 0
}

// Band names the band of a frequency: "2.4GHz", "5GHz", "6GHz" or "".
func Band(frequency int) string {
	switch {
	case frequency >= 2400 && frequency < 2500:
		return "2.4GHz"
	case frequency >= 5150 && frequency < 5925:
		return "5GHz"
	case frequency >= 5925 && frequency < 7125:
		return "6GHz"
	}
	return ""
}
