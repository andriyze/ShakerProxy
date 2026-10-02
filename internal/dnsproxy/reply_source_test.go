package dnsproxy

import (
	"context"
	"net"
	"testing"
	"time"
)

// A dual-stack listener answers IPv6 queries from the address they were sent
// to (a connected client accepts nothing else) and still answers IPv4.
func TestServerAnswersFromTheQueriedAddress(t *testing.T) {
	probe, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback here")
	}
	_ = probe.Close()
	upstream := startUpstream(t, true)
	server := &Server{Provider: staticProvider{&Runtime{Upstreams: []string{upstream}}}, Timeout: 2 * time.Second, Bind: "[::]:0"}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan [2]net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, ready) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	var port int
	select {
	case addresses := <-ready:
		port = addresses[0].(*net.UDPAddr).Port
	case err := <-done:
		t.Fatal(err)
	}
	if queries := newUDPQueries(mustListenUDP(t, "[::1]:0")); queries.ipv6 == nil {
		t.Fatal("an IPv6 listener does not read the queried address")
	}
	if queries := newUDPQueries(mustListenUDP(t, "127.0.0.1:0")); queries.ipv6 != nil {
		t.Fatal("an IPv4-only listener asked for IPv6 control messages")
	}
	for _, host := range []string{"::1", "127.0.0.1"} {
		address := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
		if response := ask(t, address, "example.com"); rcode(response) != 0 {
			t.Fatalf("%s: rcode %d", host, rcode(response))
		}
	}
}

func mustListenUDP(t *testing.T, address string) *net.UDPConn {
	t.Helper()
	resolved, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp", resolved)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}
