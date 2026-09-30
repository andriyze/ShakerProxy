package pcapng

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestRewriteRemovesOnlyExactlyMatchedPackets(t *testing.T) {
	contents := append(sectionHeader(binary.LittleEndian), interfaceBlock(binary.LittleEndian, 1)...)
	contents = append(contents, enhancedPacket(binary.LittleEndian, ethernetIPv4Endpoints([4]byte{10, 77, 0, 111}, [4]byte{10, 77, 0, 1}))...)
	contents = append(contents, enhancedPacket(binary.LittleEndian, ethernetIPv4Endpoints([4]byte{10, 77, 0, 222}, [4]byte{10, 77, 0, 1}))...)
	rule, err := CanonicalSelectionRule(nil, []string{"10.77.0.111"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	result, err := Rewrite(bytes.NewReader(contents), &output, rule)
	if err != nil {
		t.Fatal(err)
	}
	if result.PacketsRead != 2 || result.PacketsRemoved != 1 || result.PacketsWritten != 1 || result.InputBytes != uint64(len(contents)) || result.OutputBytes != uint64(output.Len()) {
		t.Fatalf("unexpected rewrite accounting: %#v", result)
	}
	verified, err := Inspect(bytes.NewReader(output.Bytes()))
	if err != nil || !verified.Exact() || verified.PacketCount != 1 || len(verified.IPAddresses) != 2 || verified.IPAddresses[1] != "10.77.0.222" {
		t.Fatalf("rewritten capture is not the exact retained population: %#v err=%v", verified, err)
	}
}

func TestRewriteUsesHalfOpenPacketTimeWindow(t *testing.T) {
	first := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	second := first.Add(time.Minute)
	contents := append(sectionHeader(binary.LittleEndian), interfaceBlock(binary.LittleEndian, 1)...)
	packet := ethernetIPv4Endpoints([4]byte{10, 77, 0, 111}, [4]byte{10, 77, 0, 1})
	contents = append(contents, enhancedPacketAt(binary.LittleEndian, packet, uint64(first.Unix())*1_000_000)...)
	contents = append(contents, enhancedPacketAt(binary.LittleEndian, packet, uint64(second.Unix())*1_000_000)...)
	start, end := second, second.Add(time.Minute)
	rule, err := CanonicalSelectionRule(nil, []string{"10.77.0.111"}, &start, &end)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	result, err := Rewrite(bytes.NewReader(contents), &output, rule)
	if err != nil || result.PacketsRemoved != 1 || result.PacketsWritten != 1 {
		t.Fatalf("time-bounded selection was not exact: %#v err=%v", result, err)
	}
}

func TestRewriteRefusesInexactPacketClassification(t *testing.T) {
	for name, testCase := range map[string]struct {
		linkType uint16
		packet   []byte
	}{
		"unsupported link": {147, []byte{1, 2, 3, 4}},
		"truncated header": {1, []byte{1, 2, 3, 4}},
	} {
		t.Run(name, func(t *testing.T) {
			contents := append(sectionHeader(binary.LittleEndian), interfaceBlock(binary.LittleEndian, testCase.linkType)...)
			contents = append(contents, enhancedPacket(binary.LittleEndian, testCase.packet)...)
			rule, err := CanonicalSelectionRule([]string{"02:00:00:00:00:01"}, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Rewrite(bytes.NewReader(contents), &bytes.Buffer{}, rule); !errors.Is(err, ErrInexactSelection) {
				t.Fatalf("inexact packet population was rewritten: %v", err)
			}
		})
	}
}

func TestCanonicalSelectionRuleRejectsInvalidOrPartialBounds(t *testing.T) {
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	if _, err := CanonicalSelectionRule(nil, []string{"10.0.0.1", "10.0.0.1"}, &start, nil); err == nil {
		t.Fatal("selection with one time bound was accepted")
	}
	rule, err := CanonicalSelectionRule([]string{"02:00:00:00:00:02", "02:00:00:00:00:01", "02:00:00:00:00:02"}, nil, nil, nil)
	if err != nil || len(rule.Identities) != 2 || rule.Identities[0].Value != "02:00:00:00:00:01" {
		t.Fatalf("selection was not canonicalized: %#v err=%v", rule, err)
	}
}

func TestCanonicalWindowedSelectionMergesOnlySameIdentityIntervals(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	firstEnd, secondStart, secondEnd := base.Add(time.Hour), base.Add(30*time.Minute), base.Add(2*time.Hour)
	rule, err := CanonicalWindowedSelectionRule([]SelectionIdentity{
		{Kind: SelectionIdentityIP, Value: "10.77.0.111", StartAt: &base, EndAt: &firstEnd},
		{Kind: SelectionIdentityIP, Value: "10.77.0.111", StartAt: &secondStart, EndAt: &secondEnd},
		{Kind: SelectionIdentityIP, Value: "10.77.0.222", StartAt: &secondStart, EndAt: &secondEnd},
	})
	if err != nil || len(rule.Identities) != 2 || !rule.Identities[0].StartAt.Equal(base) || !rule.Identities[0].EndAt.Equal(secondEnd) {
		t.Fatalf("identity validity intervals were not canonically merged: %#v err=%v", rule, err)
	}
}

func TestRewriteHonorsCancellationBeforeWriting(t *testing.T) {
	rule, err := CanonicalSelectionRule([]string{"02:00:00:00:00:01"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var output bytes.Buffer
	if _, err := RewriteContext(ctx, bytes.NewReader(sectionHeader(binary.LittleEndian)), &output, rule); !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatalf("cancelled rewrite wrote output: bytes=%d err=%v", output.Len(), err)
	}
}

func FuzzRewriteNeverPanics(f *testing.F) {
	rule, err := CanonicalSelectionRule([]string{"02:00:00:00:00:01"}, nil, nil, nil)
	if err != nil {
		f.Fatal(err)
	}
	valid := append(sectionHeader(binary.LittleEndian), interfaceBlock(binary.LittleEndian, 1)...)
	valid = append(valid, enhancedPacket(binary.LittleEndian, ethernetIPv4Packet(false))...)
	f.Add([]byte{})
	f.Add(valid)
	f.Fuzz(func(t *testing.T, contents []byte) {
		var output bytes.Buffer
		result, err := Rewrite(bytes.NewReader(contents), &output, rule)
		if err != nil {
			return
		}
		membership, inspectErr := Inspect(bytes.NewReader(output.Bytes()))
		if inspectErr != nil || result.PacketsRead != result.PacketsWritten+result.PacketsRemoved || result.OutputBytes != uint64(output.Len()) || !membership.Exact() || membership.PacketCount != result.PacketsWritten {
			t.Fatalf("successful rewrite returned inconsistent output: %#v membership=%#v err=%v", result, membership, inspectErr)
		}
	})
}

func ethernetIPv4Endpoints(source, destination [4]byte) []byte {
	packet := ethernetIPv4Packet(false)
	copy(packet[26:30], source[:])
	copy(packet[30:34], destination[:])
	return packet
}
