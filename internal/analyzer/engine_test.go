package analyzer

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestZeekArgumentsLoadSitePolicyWithoutDeterministicMode(t *testing.T) {
	expected := []string{"-C", "-r", "/proc/self/fd/3", "LogAscii::use_json=T", "/etc/shakerproxy/zeek/shakerproxy.zeek"}
	if arguments := zeekArguments(); !reflect.DeepEqual(arguments, expected) {
		t.Fatalf("unexpected Zeek arguments:\nwant %q\n got %q", expected, arguments)
	}
	for _, argument := range zeekArguments() {
		if argument == "-D" || argument == "--deterministic" {
			t.Fatal("Zeek deterministic mode would make connection UIDs collide across captures")
		}
	}
}

// pcapngFixture builds a little-endian PCAPNG file: a section header, one
// interface, and the given number of enhanced packet blocks.
func pcapngFixture(t *testing.T, packets int) *os.File {
	t.Helper()
	var data []byte
	block := func(blockType uint32, body []byte) {
		length := uint32(12 + len(body))
		header := make([]byte, 8)
		binary.LittleEndian.PutUint32(header[:4], blockType)
		binary.LittleEndian.PutUint32(header[4:], length)
		trailer := make([]byte, 4)
		binary.LittleEndian.PutUint32(trailer, length)
		data = append(append(append(data, header...), body...), trailer...)
	}
	section := make([]byte, 16)
	binary.LittleEndian.PutUint32(section[:4], 0x1A2B3C4D)
	binary.LittleEndian.PutUint16(section[4:6], 1)
	binary.LittleEndian.PutUint64(section[8:], ^uint64(0))
	block(0x0A0D0D0A, section)
	block(1, []byte{1, 0, 0, 0, 0, 0, 4, 0}) // Ethernet, snaplen 262144
	for index := 0; index < packets; index++ {
		packet := make([]byte, 20+64)
		binary.LittleEndian.PutUint32(packet[12:16], 64)
		binary.LittleEndian.PutUint32(packet[16:20], 64)
		block(6, packet)
	}
	path := filepath.Join(t.TempDir(), "segment.pcapng")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}

// A segment from a quiet 30 s holds no packets; Suricata exits 1 on it, which
// stopped all Suricata analysis of the automatic lab recording.
func TestEmptyCaptureSegmentsAreNotHandedToTheEngine(t *testing.T) {
	if captureHasPackets(pcapngFixture(t, 0)) {
		t.Fatal("a header-only PCAPNG reported packets")
	}
	if !captureHasPackets(pcapngFixture(t, 2)) {
		t.Fatal("a PCAPNG with packets reported none")
	}
	events, err := CommandProcessor{Engine: EngineSuricata}.Analyze(context.Background(), pcapngFixture(t, 0), t.TempDir())
	if err != nil || len(events) != 0 {
		t.Fatalf("an empty segment was not analyzed as empty: events=%v err=%v", events, err)
	}
	// Anything that is not PCAPNG goes to the engine, which decides.
	path := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(path, []byte("bounded-pcap-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, _ := os.Open(path)
	defer other.Close()
	if !captureHasPackets(other) {
		t.Fatal("an unrecognised file was treated as empty")
	}
}
