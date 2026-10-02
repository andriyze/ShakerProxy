package analyzer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

type livePacket struct {
	at   time.Time
	data []byte
}

// pcapngSection builds one dumpcap-style segment: a section header, one
// interface with the given link type and timestamp resolution (0: the
// microsecond default), and a packet block per packet.
func pcapngSection(order binary.ByteOrder, linkType uint16, resolution byte, packets []livePacket) []byte {
	var data []byte
	block := func(blockType uint32, body []byte) {
		length := uint32(12 + len(body))
		header := make([]byte, 8)
		order.PutUint32(header[:4], blockType)
		order.PutUint32(header[4:], length)
		trailer := make([]byte, 4)
		order.PutUint32(trailer, length)
		data = append(append(append(data, header...), body...), trailer...)
	}
	section := make([]byte, 16)
	order.PutUint32(section[:4], pcapngByteOrderMagic)
	order.PutUint16(section[4:6], 1)
	order.PutUint64(section[8:], ^uint64(0))
	block(pcapngSectionHeader, section)
	iface := make([]byte, 8)
	order.PutUint16(iface[:2], linkType)
	order.PutUint32(iface[4:], 262144)
	unitsPerSecond := uint64(1_000_000)
	if resolution != 0 {
		option := make([]byte, 8)
		order.PutUint16(option[:2], 9)
		order.PutUint16(option[2:4], 1)
		option[4] = resolution
		iface = append(append(iface, option...), 0, 0, 0, 0)
		unitsPerSecond = 1
		for range resolution {
			unitsPerSecond *= 10
		}
	}
	block(pcapngInterface, iface)
	for _, packet := range packets {
		units := uint64(packet.at.Unix())*unitsPerSecond + uint64(packet.at.Nanosecond())*unitsPerSecond/1_000_000_000
		padded := len(packet.data) + (4-len(packet.data)%4)%4
		body := make([]byte, 20+padded)
		order.PutUint32(body[4:8], uint32(units>>32))
		order.PutUint32(body[8:12], uint32(units))
		order.PutUint32(body[12:16], uint32(len(packet.data)))
		order.PutUint32(body[16:20], uint32(len(packet.data)))
		copy(body[20:], packet.data)
		block(pcapngEnhancedPacket, body)
	}
	return data
}

type pcapRecord struct {
	seconds, micros uint32
	data            []byte
}

func parsePcapStream(t *testing.T, stream []byte) (uint32, []pcapRecord) {
	t.Helper()
	if len(stream) < 24 || binary.LittleEndian.Uint32(stream[:4]) != pcapMagicMicroseconds {
		t.Fatalf("stream has no classic pcap header: %x", stream[:min(len(stream), 24)])
	}
	linkType := binary.LittleEndian.Uint32(stream[20:24])
	var records []pcapRecord
	for offset := 24; offset < len(stream); {
		length := int(binary.LittleEndian.Uint32(stream[offset+8 : offset+12]))
		records = append(records, pcapRecord{
			seconds: binary.LittleEndian.Uint32(stream[offset : offset+4]), micros: binary.LittleEndian.Uint32(stream[offset+4 : offset+8]),
			data: stream[offset+16 : offset+16+length],
		})
		offset += 16 + length
	}
	return linkType, records
}

func frame(id byte) []byte {
	data := make([]byte, 61)
	binary.BigEndian.PutUint16(data[12:14], 0x0800)
	data[14] = id
	return data
}

// dumpcap writes each ring-buffer segment as its own PCAPNG section, but
// libpcap stops at a stream's second section header, so live analysis must
// hand Zeek one classic pcap stream, however the bytes arrive.
func TestLivePcapStreamJoinsSegmentsReadInArbitraryChunks(t *testing.T) {
	base := time.Date(2026, 10, 2, 10, 0, 0, 123456000, time.UTC)
	first := pcapngSection(binary.LittleEndian, 1, 0, []livePacket{{base, frame(1)}, {base.Add(time.Second), frame(2)}})
	second := pcapngSection(binary.LittleEndian, 1, 0, []livePacket{{base.Add(2 * time.Second), frame(3)}})
	var whole, chunked bytes.Buffer
	converter := newPcapngToPcap()
	for _, segment := range [][]byte{first, second} {
		if err := converter.Feed(segment, &whole); err != nil {
			t.Fatal(err)
		}
	}
	converter = newPcapngToPcap()
	for _, segment := range [][]byte{first, second} {
		for offset := 0; offset < len(segment); offset += 7 {
			if err := converter.Feed(segment[offset:min(offset+7, len(segment))], &chunked); err != nil {
				t.Fatal(err)
			}
		}
		if converter.Pending() != 0 {
			t.Fatalf("a complete segment left %d bytes pending", converter.Pending())
		}
	}
	if !bytes.Equal(whole.Bytes(), chunked.Bytes()) {
		t.Fatal("chunked reads produced a different stream")
	}
	linkType, records := parsePcapStream(t, whole.Bytes())
	if linkType != 1 || len(records) != 3 || converter.Packets != 3 {
		t.Fatalf("link type %d, %d records, %d packets", linkType, len(records), converter.Packets)
	}
	for index, record := range records {
		want := base.Add(time.Duration(index) * time.Second)
		if record.seconds != uint32(want.Unix()) || record.micros != 123456 || record.data[14] != byte(index+1) || len(record.data) != 61 {
			t.Fatalf("record %d = %d.%06d id %d len %d", index, record.seconds, record.micros, record.data[14], len(record.data))
		}
	}
}

func TestLivePcapStreamConvertsByteOrderAndTimestampResolution(t *testing.T) {
	at := time.Date(2026, 10, 2, 10, 0, 0, 987654321, time.UTC)
	var out bytes.Buffer
	if err := newPcapngToPcap().Feed(pcapngSection(binary.BigEndian, 1, 9, []livePacket{{at, frame(7)}}), &out); err != nil {
		t.Fatal(err)
	}
	_, records := parsePcapStream(t, out.Bytes())
	if len(records) != 1 || records[0].seconds != uint32(at.Unix()) || records[0].micros != 987654 || records[0].data[14] != 7 {
		t.Fatalf("records = %#v", records)
	}
}

func TestLivePcapStreamWaitsForTheRestOfABlock(t *testing.T) {
	at := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	segment := pcapngSection(binary.LittleEndian, 1, 0, []livePacket{{at, frame(1)}, {at, frame(2)}})
	converter := newPcapngToPcap()
	var out bytes.Buffer
	if err := converter.Feed(segment[:len(segment)-3], &out); err != nil {
		t.Fatal(err)
	}
	if converter.Packets != 1 || converter.Pending() == 0 {
		t.Fatalf("packets %d pending %d", converter.Packets, converter.Pending())
	}
	if err := converter.Feed(segment[len(segment)-3:], &out); err != nil || converter.Packets != 2 || converter.Pending() != 0 {
		t.Fatalf("the completed block was not converted: err=%v packets=%d", err, converter.Packets)
	}
}

func TestLivePcapStreamRejectsMalformedSegments(t *testing.T) {
	at := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	converter := newPcapngToPcap()
	if err := converter.Feed(pcapngSection(binary.LittleEndian, 1, 0, []livePacket{{at, frame(1)}}), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := converter.Feed(pcapngSection(binary.LittleEndian, 113, 0, nil), &bytes.Buffer{}); !errors.Is(err, errLiveLinkTypeChanged) {
		t.Fatalf("a link type change was accepted: %v", err)
	}
	if err := newPcapngToPcap().Feed(bytes.Repeat([]byte{0xff}, 32), &bytes.Buffer{}); err == nil {
		t.Fatal("bytes without a section header were accepted")
	}
	corrupt := pcapngSection(binary.LittleEndian, 1, 0, []livePacket{{at, frame(1)}})
	binary.LittleEndian.PutUint32(corrupt[len(corrupt)-4:], 999)
	if err := newPcapngToPcap().Feed(corrupt, &bytes.Buffer{}); err == nil {
		t.Fatal("a block with a mismatched trailing length was accepted")
	}
}

// Reading a trace, Zeek's clock moves only with packets; ticks keep it moving
// while the lab is quiet, but never backwards and never before the stream
// has a header.
func TestLivePcapTicksOnlyMoveZeeksClockForward(t *testing.T) {
	at := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	converter := newPcapngToPcap()
	var out bytes.Buffer
	if ticked, err := converter.Tick(at, &out); ticked || err != nil || out.Len() != 0 {
		t.Fatalf("ticked before the stream had a header: %v %v", ticked, err)
	}
	if err := converter.Feed(pcapngSection(binary.LittleEndian, 1, 0, []livePacket{{at, frame(1)}}), &out); err != nil {
		t.Fatal(err)
	}
	if ticked, _ := converter.Tick(at.Add(-time.Second), &out); ticked {
		t.Fatal("a tick moved the clock backwards")
	}
	if ticked, err := converter.Tick(at.Add(time.Second), &out); !ticked || err != nil {
		t.Fatalf("no tick after the last packet: %v %v", ticked, err)
	}
	if ticked, _ := converter.Tick(at.Add(time.Second), &out); ticked {
		t.Fatal("a tick repeated the clock")
	}
	_, records := parsePcapStream(t, out.Bytes())
	tick := records[len(records)-1]
	if len(records) != 2 || tick.seconds != uint32(at.Unix()+1) || len(tick.data) != 60 || binary.BigEndian.Uint16(tick.data[12:14]) != 0x88B5 || !converter.lastPacket.Equal(at) {
		t.Fatalf("records = %#v", records)
	}
	sll := newPcapngToPcap()
	if err := sll.Feed(pcapngSection(binary.LittleEndian, 113, 0, []livePacket{{at, frame(1)}}), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if ticked, _ := sll.Tick(at.Add(time.Second), &bytes.Buffer{}); ticked {
		t.Fatal("ticked on a link type without an ignorable frame")
	}
}
