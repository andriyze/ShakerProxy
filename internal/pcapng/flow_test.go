package pcapng_test

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
	"shakerproxy.dev/shakerproxy/internal/pcapng/pcapngtest"
)

var (
	phone  = netip.MustParseAddrPort("192.168.10.201:41234")
	server = netip.MustParseAddrPort("93.184.216.34:80")
	start  = time.Date(2026, 10, 2, 3, 30, 0, 0, time.UTC)
	limits = pcapng.TCPFlowLimits{MaxPackets: 1000, MaxPayloadBytes: 1 << 20}
)

func scan(t *testing.T, file []byte, key pcapng.TCPFlowKey, from, to time.Time) pcapng.TCPFlowScan {
	t.Helper()
	var result pcapng.TCPFlowScan
	if err := pcapng.ScanTCPFlow(context.Background(), bytes.NewReader(file), key, from, to, limits, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestKeepAliveConnectionReassemblesDespiteReorderingAndRetransmission(t *testing.T) {
	conversation := pcapngtest.NewKeepAliveHTTP(start)
	packets := conversation.Packets
	// Another connection of the same phone, and a packet of this connection
	// outside the window, must be ignored.
	other := netip.MustParseAddrPort("192.168.10.201:41235")
	packets = append(packets, pcapngtest.Packet{At: start.Add(50 * time.Millisecond), FromClient: true, Seq: 9, Flags: pcapngtest.FlagACK, Payload: []byte("GET /other HTTP/1.1\r\n\r\n")})
	file := pcapngtest.Conversation(phone, server, conversation.Packets)
	file = append(file, pcapngtest.Conversation(other, server, packets[len(packets)-1:])[48:]...)
	late := pcapngtest.Conversation(phone, server, []pcapngtest.Packet{{At: start.Add(time.Hour), FromClient: true, Seq: 1, Payload: []byte("late")}})
	file = append(file, late[48:]...)

	result := scan(t, file, pcapng.TCPFlowKey{Client: phone, Server: server}, start.Add(-time.Minute), start.Add(time.Minute))
	if len(result.Segments) != len(conversation.Packets) {
		t.Fatalf("matched %d packets, want %d", len(result.Segments), len(conversation.Packets))
	}
	client := pcapng.ReassembleTCP(result.Segments, true, 1<<20)
	server := pcapng.ReassembleTCP(result.Segments, false, 1<<20)
	if !bytes.Equal(client.Data, conversation.Client) || client.Gap || !client.FromStart || !client.FIN {
		t.Fatalf("client stream = %q gap=%v fromStart=%v", client.Data, client.Gap, client.FromStart)
	}
	if !bytes.Equal(server.Data, conversation.Server) || server.Gap {
		t.Fatalf("server stream = %q gap=%v", server.Data, server.Gap)
	}
	bounded := pcapng.ReassembleTCP(result.Segments, true, 16)
	if len(bounded.Data) != 16 || !bounded.Truncated {
		t.Fatalf("stream bound not applied: %d bytes truncated=%v", len(bounded.Data), bounded.Truncated)
	}
}

func TestIPv6ConnectionsAreSelectedToo(t *testing.T) {
	client := netip.MustParseAddrPort("[2001:db8::201]:41234")
	host := netip.MustParseAddrPort("[2001:db8::80]:80")
	file := pcapngtest.Conversation(client, host, []pcapngtest.Packet{{At: start, FromClient: true, Seq: 7, Flags: pcapngtest.FlagACK, Payload: []byte("GET / HTTP/1.1\r\n\r\n")}})
	result := scan(t, file, pcapng.TCPFlowKey{Client: client, Server: host}, start.Add(-time.Second), start.Add(time.Second))
	if stream := pcapng.ReassembleTCP(result.Segments, true, 1024); string(stream.Data) != "GET / HTTP/1.1\r\n\r\n" {
		t.Fatalf("IPv6 stream = %q", stream.Data)
	}
}

func TestSnapLengthCutAndMidStreamGapsAreReported(t *testing.T) {
	file := pcapngtest.Conversation(phone, server, []pcapngtest.Packet{
		// No SYN: the recording starts mid-connection.
		{At: start, FromClient: true, Seq: 0xfffffff0, Flags: pcapngtest.FlagACK, Payload: []byte("0123456789abcdef")},
		// Wraps around 2^32; then a missing segment leaves a gap.
		{At: start.Add(time.Millisecond), FromClient: true, Seq: 0x00000000, Flags: pcapngtest.FlagACK, Payload: []byte("WRAPPED")},
		{At: start.Add(2 * time.Millisecond), FromClient: true, Seq: 0x00000100, Flags: pcapngtest.FlagACK, Payload: []byte("after a gap")},
		// A headers-only capture cut this response's payload.
		{At: start.Add(3 * time.Millisecond), FromClient: false, Seq: 1, Flags: pcapngtest.FlagACK, Payload: bytes.Repeat([]byte("x"), 400), Snap: 96},
	})
	result := scan(t, file, pcapng.TCPFlowKey{Client: phone, Server: server}, start.Add(-time.Second), start.Add(time.Second))
	client := pcapng.ReassembleTCP(result.Segments, true, 1024)
	if string(client.Data) != "0123456789abcdefWRAPPED" || !client.Gap || client.GapAt != 23 || client.FromStart {
		t.Fatalf("mid-stream reassembly = %q gap=%v at %d fromStart=%v", client.Data, client.Gap, client.GapAt, client.FromStart)
	}
	if server := pcapng.ReassembleTCP(result.Segments, false, 1024); !server.Cut {
		t.Fatal("a payload cut by the snap length was not reported")
	}
}

func TestFlowScanStopsAtItsLimits(t *testing.T) {
	conversation := pcapngtest.NewKeepAliveHTTP(start)
	file := pcapngtest.Conversation(phone, server, conversation.Packets)
	var result pcapng.TCPFlowScan
	if err := pcapng.ScanTCPFlow(context.Background(), bytes.NewReader(file), pcapng.TCPFlowKey{Client: phone, Server: server}, start.Add(-time.Minute), start.Add(time.Minute), pcapng.TCPFlowLimits{MaxPackets: 3, MaxPayloadBytes: 1 << 20}, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Segments) != 3 || !result.LimitReached {
		t.Fatalf("packet bound not applied: %d segments limit=%v", len(result.Segments), result.LimitReached)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pcapng.ScanTCPFlow(ctx, bytes.NewReader(file), pcapng.TCPFlowKey{Client: phone, Server: server}, start, start.Add(time.Minute), limits, &pcapng.TCPFlowScan{}); err == nil {
		t.Fatal("a cancelled scan kept reading")
	}
}

func FuzzScanTCPFlowNeverPanics(f *testing.F) {
	f.Add(pcapngtest.Conversation(phone, server, pcapngtest.NewKeepAliveHTTP(start).Packets))
	f.Fuzz(func(t *testing.T, data []byte) {
		var result pcapng.TCPFlowScan
		_ = pcapng.ScanTCPFlow(context.Background(), bytes.NewReader(data), pcapng.TCPFlowKey{Client: phone, Server: server}, time.Time{}, start.Add(time.Hour), limits, &result)
		_ = pcapng.ReassembleTCP(result.Segments, true, 4096)
		_ = pcapng.ReassembleTCP(result.Segments, false, 4096)
	})
}
