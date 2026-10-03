package syslogcollector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type captureSink struct {
	mu        sync.Mutex
	envelopes []ingest.Envelope
	failNext  bool
}

func (c *captureSink) Deliver(_ context.Context, envelope ingest.Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failNext {
		c.failNext = false
		return fmt.Errorf("sink unavailable")
	}
	c.envelopes = append(c.envelopes, envelope)
	return nil
}

func (c *captureSink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.envelopes)
}

func TestReadFrameSupportsBothFramings(t *testing.T) {
	message := "<30>Oct  2 23:48:30 host app: hello"
	octet := fmt.Sprintf("%d %s", len(message), message)
	stream := octet + message + "\n" + message + "\x00"
	reader := bufio.NewReader(bytes.NewReader([]byte(stream)))
	for index := 0; index < 3; index++ {
		frame, err := ReadFrame(reader)
		if err != nil {
			t.Fatalf("frame %d: %v", index, err)
		}
		if string(frame) != message {
			t.Fatalf("frame %d = %q, want %q", index, frame, message)
		}
	}
	if _, err := ReadFrame(reader); err == nil {
		t.Fatal("expected EOF after the last frame")
	}
}

func TestReadFrameRejectsOversizeOctetCount(t *testing.T) {
	reader := bufio.NewReader(bytes.NewReader([]byte("99999999 x")))
	if _, err := ReadFrame(reader); err == nil {
		t.Fatal("expected an oversize octet count to be rejected")
	}
}

func TestReceiverAcceptsOnlyAllowedSourcesOverUDP(t *testing.T) {
	sink := &captureSink{}
	router := netip.MustParseAddr("127.0.0.1")
	receiver, err := NewReceiver(Config{Enabled: true, BindAddress: "127.0.0.1:0", EnableUDP: true, EnableTCP: false, AllowedSources: []netip.Addr{router}}, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Bind explicitly so the test can learn the port, then drive serveUDP.
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var group sync.WaitGroup
	group.Add(1)
	go func() { defer group.Done(); _ = receiver.serveUDP(ctx, packet) }()

	target := packet.LocalAddr().String()
	client, err := net.Dial("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	line := "<30>Oct  2 23:48:30 UDMPRO dnsmasq-dhcp[1]: DHCPACK(br0) 192.168.10.130 62:bc:f1:bc:1d:8d iPhone"
	if _, err := client.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return sink.count() == 1 })
	client.Close()
	cancel()
	group.Wait()

	stats := receiver.Stats()
	if stats.Delivered != 1 || stats.Parsed != 1 || stats.Rejected != 0 {
		t.Fatalf("allowed-source stats: %+v", stats)
	}
	if len(sink.envelopes) != 1 || sink.envelopes[0].Kind != ingest.NetworkGearDHCPKind {
		t.Fatalf("delivered: %#v", sink.envelopes)
	}
}

func TestReceiverIngestEnforcesRateLimitAndAllowlist(t *testing.T) {
	sink := &captureSink{}
	allowed := netip.MustParseAddr("192.168.10.1")
	receiver, err := NewReceiver(Config{Enabled: true, EnableTCP: true, AllowedSources: []netip.Addr{allowed}, PerSourceRate: 1, BurstPerSource: 2, GlobalRate: 1000, GlobalBurst: 1000}, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A frozen clock makes the token bucket deterministic.
	frozen := time.Date(2026, 10, 2, 23, 48, 30, 0, time.UTC)
	receiver.now = func() time.Time { return frozen }
	line := []byte("<30>Oct  2 23:48:30 UDMPRO dnsmasq-dhcp[1]: DHCPACK(br0) 192.168.10.130 62:bc:f1:bc:1d:8d iPhone")
	for index := 0; index < 5; index++ {
		receiver.ingest(context.Background(), allowed, line)
	}
	receiver.drain(context.Background())
	// An address that is not allowed never reaches ingest in the server loops,
	// but allowAddr is the gate; confirm it rejects a stranger.
	if receiver.allowAddr(netip.MustParseAddr("10.9.9.9")) {
		t.Fatal("a non-allowlisted source was allowed")
	}
	stats := receiver.Stats()
	// Burst of 2 tokens, no refill at a frozen clock: 2 delivered, 3 dropped.
	if stats.Delivered != 2 || stats.Dropped != 3 {
		t.Fatalf("rate-limit stats: %+v", stats)
	}
}

func TestReceiverCountsDeliveryErrorsAndUnparsed(t *testing.T) {
	sink := &captureSink{failNext: true}
	allowed := netip.MustParseAddr("192.168.10.1")
	receiver, _ := NewReceiver(Config{Enabled: true, AllowedSources: []netip.Addr{allowed}}, sink, nil)
	dhcp := []byte("<30>Oct  2 23:48:30 h dnsmasq-dhcp[1]: DHCPACK(br0) 192.168.10.130 62:bc:f1:bc:1d:8d iPhone")
	noise := []byte("<30>Oct  2 23:48:30 h sshd: accepted login")
	receiver.ingest(context.Background(), allowed, dhcp)  // sink fails
	receiver.ingest(context.Background(), allowed, dhcp)  // delivered
	receiver.ingest(context.Background(), allowed, noise) // unparsed
	receiver.drain(context.Background())
	stats := receiver.Stats()
	if stats.DeliverErr != 1 || stats.Delivered != 1 || stats.Unparsed != 1 || stats.Parsed != 2 {
		t.Fatalf("mixed stats: %+v", stats)
	}
	if entry := stats.PerSource[allowed.String()]; entry.Received != 3 || entry.Parsed != 2 {
		t.Fatalf("per-source: %+v", entry)
	}
}

func TestDisabledReceiverRunsNothing(t *testing.T) {
	receiver, err := NewReceiver(Config{Enabled: false}, &captureSink{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Run(context.Background()); err != nil {
		t.Fatalf("disabled receiver returned %v", err)
	}
}

func TestBucketRefills(t *testing.T) {
	b := newBucket(10, 2)
	start := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	if !b.allow(start) || !b.allow(start) || b.allow(start) {
		t.Fatal("burst of 2 should allow exactly two immediately")
	}
	if b.allow(start.Add(50 * time.Millisecond)) {
		t.Fatal("no token should be available after 50ms at 10/s")
	}
	if !b.allow(start.Add(150 * time.Millisecond)) {
		t.Fatal("a token should have refilled after 150ms at 10/s")
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before the deadline")
}

// A slow sink never stalls receiving: events queue for the delivery worker,
// and past the queue's bound they are counted, not waited on.
func TestReceiverQueuesDeliveryInsteadOfBlocking(t *testing.T) {
	blocked := make(chan struct{})
	sink := sinkFunc(func(ctx context.Context, _ ingest.Envelope) error {
		select {
		case <-blocked:
		case <-ctx.Done():
		}
		return nil
	})
	allowed := netip.MustParseAddr("192.168.10.1")
	receiver, _ := NewReceiver(Config{Enabled: true, AllowedSources: []netip.Addr{allowed}, PerSourceRate: 1e6, BurstPerSource: 1e6, GlobalRate: 1e6, GlobalBurst: 1e6}, sink, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	receiver.startDelivery(ctx)
	line := []byte("<30>Oct  2 23:48:30 h dnsmasq-dhcp[1]: DHCPACK(br0) 192.168.10.130 62:bc:f1:bc:1d:8d iPhone")
	started := time.Now()
	for index := 0; index < deliveryQueueSize+10; index++ {
		receiver.ingest(ctx, allowed, line)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("receiving waited on the sink for %v", elapsed)
	}
	if stats := receiver.Stats(); stats.Backlog == 0 || stats.Parsed != deliveryQueueSize+10 {
		t.Fatalf("stats = %+v", stats)
	}
	close(blocked)
}

type sinkFunc func(context.Context, ingest.Envelope) error

func (f sinkFunc) Deliver(ctx context.Context, envelope ingest.Envelope) error {
	return f(ctx, envelope)
}

// Shutdown does not wait for an idle TCP sender's read deadline.
func TestReceiverStopsPromptlyWithAnIdleTCPSender(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	probe.Close()
	receiver, _ := NewReceiver(Config{Enabled: true, BindAddress: address, EnableTCP: true, AllowedSources: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, &captureSink{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- receiver.Run(ctx) }()
	waitFor(t, receiver.Listening)
	client, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	time.Sleep(50 * time.Millisecond) // the connection is accepted and idle
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run waited on the idle connection")
	}
}

// When the second socket cannot be bound the first is released, so the next
// attempt can bind both.
func TestReceiverReleasesTheFirstSocketWhenTheSecondFails(t *testing.T) {
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	address := taken.LocalAddr().String()
	receiver, _ := NewReceiver(Config{Enabled: true, BindAddress: address, EnableTCP: true, EnableUDP: true, AllowedSources: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, &captureSink{}, nil)
	if err := receiver.Run(context.Background()); err == nil {
		t.Fatal("Run succeeded with its UDP port taken")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("the TCP socket was not released: %v", err)
	}
	listener.Close()
}
