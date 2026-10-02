package daemon

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/conntrack"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/hostevents"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

func singleArmLabStore() *StateStore {
	return &StateStore{state: persistedState{
		OperatingMode: gatewayprotocol.ModeRouted,
		StagedNetworkPlan: &networkplan.StagedPlan{
			Plan: networkplan.Plan{
				IPv4:       networkplan.IPv4Configuration{Enabled: true, LabCIDR: "192.168.10.0/24", GatewayAddress: "192.168.10.177", NAT44: true},
				Interfaces: []networkplan.Interface{{CurrentName: "ens18", Role: networkplan.RoleLab}},
			},
			Transaction: &networktransaction.Record{Phase: networktransaction.PhaseConfirmed},
		},
	}}
}

func connectionEvent(protocol, source, destination string) conntrack.Event {
	return conntrack.Event{Protocol: protocol, Source: netip.MustParseAddrPort(source), Destination: netip.MustParseAddrPort(destination)}
}

func TestConnectionScopeKeepsLabTrafficToElsewhereOnly(t *testing.T) {
	scope := labConnectionScope(singleArmLabStore(), nil)
	if scope == nil {
		t.Fatal("a confirmed single-arm plan has no connection scope")
	}
	for _, check := range []struct {
		event conntrack.Event
		want  bool
		why   string
	}{
		{connectionEvent("tcp", "192.168.10.201:37064", "140.82.121.4:443"), true, "the phone to github.com"},
		{connectionEvent("udp", "192.168.10.201:50000", "142.250.1.1:443"), true, "QUIC to Google"},
		{connectionEvent("udp", "192.168.10.201:41000", "192.168.10.177:53"), false, "DNS to the gateway (dnsd records it)"},
		{connectionEvent("tcp", "192.168.10.201:41000", "192.168.10.177:8443"), false, "the gateway's own services"},
		{connectionEvent("tcp", "192.168.10.177:50000", "1.1.1.1:443"), false, "the gateway's own connections"},
		{connectionEvent("udp", "172.18.0.5:41000", "1.1.1.1:53"), false, "a container, not a lab device"},
		{connectionEvent("udp", "192.168.10.201:5353", "224.0.0.251:5353"), false, "mDNS multicast"},
		{connectionEvent("udp", "192.168.10.201:68", "255.255.255.255:67"), false, "limited broadcast"},
		{connectionEvent("udp", "192.168.10.201:137", "192.168.10.255:137"), false, "the lab broadcast address"},
		{connectionEvent("tcp", "192.168.10.201:41000", "192.168.10.50:8009"), true, "another lab device through the gateway"},
	} {
		if got := scope.wants(check.event); got != check.want {
			t.Fatalf("%s: wants = %v", check.why, got)
		}
	}
	off := singleArmLabStore()
	off.state.OperatingMode = gatewayprotocol.ModeSetupSafe
	if labConnectionScope(off, nil) != nil {
		t.Fatal("connections are reported while the lab is off")
	}
}

type fakeConnectionSource struct {
	events []conntrack.Event
}

func (f *fakeConnectionSource) Run(ctx context.Context, handle func(conntrack.Event)) error {
	for _, event := range f.events {
		handle(event)
	}
	<-ctx.Done()
	return nil
}

func (f *fakeConnectionSource) Dropped() uint64 { return 0 }

func TestConnectionReporterSpoolsLabConnectionsAsHostEvents(t *testing.T) {
	directory := t.TempDir()
	spool, err := hostevents.New(directory, "connections", nil)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 2, 3, 34, 36, 0, time.UTC)
	source := &fakeConnectionSource{events: []conntrack.Event{
		connectionEvent("tcp", "192.168.10.201:37064", "140.82.121.4:443"),
		connectionEvent("udp", "192.168.10.201:41000", "192.168.10.177:53"),
	}}
	reporter := &ConnectionReporter{Store: singleArmLabStore(), Spool: spool, Now: func() time.Time { return at }, Listen: func() (connectionSource, error) { return source, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reporter.Run(ctx)
		close(done)
	}()
	var files []string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entries, _ := os.ReadDir(directory)
		files = files[:0]
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "evt_") {
				files = append(files, entry.Name())
			}
		}
		if len(files) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if len(files) != 1 {
		t.Fatalf("spooled %d events, want only the phone's connection to github.com: %v", len(files), files)
	}
	raw, err := os.ReadFile(filepath.Join(directory, files[0]))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		EventID    string    `json:"event_id"`
		Source     string    `json:"source"`
		Kind       string    `json:"kind"`
		OccurredAt time.Time `json:"occurred_at"`
		Payload    struct {
			SourceIP        string `json:"source_ip"`
			SourcePort      int    `json:"source_port"`
			DestinationIP   string `json:"destination_ip"`
			DestinationPort int    `json:"destination_port"`
			Protocol        string `json:"protocol"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Source != "HOST" || envelope.Kind != conntrack.EventKind || !envelope.OccurredAt.Equal(at) || envelope.EventID+".json" != files[0] ||
		envelope.Payload.SourceIP != "192.168.10.201" || envelope.Payload.SourcePort != 37064 || envelope.Payload.DestinationIP != "140.82.121.4" || envelope.Payload.DestinationPort != 443 || envelope.Payload.Protocol != "tcp" {
		t.Fatalf("connection event = %s", raw)
	}
}

func TestConnectionReporterNeverBlocksWhenTheSpoolQueueIsFull(t *testing.T) {
	spool, err := hostevents.New(t.TempDir(), "connections", nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter := &ConnectionReporter{Store: singleArmLabStore(), Spool: spool}
	reporter.refreshScope()
	finished := make(chan struct{})
	go func() {
		// Nothing drains the queue: Handle must still return every time.
		for index := 0; index < 10000; index++ {
			reporter.Handle(connectionEvent("tcp", "192.168.10.201:37064", "140.82.121.4:443"))
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle blocked on a full queue")
	}
	if spool.Dropped() == 0 {
		t.Fatal("events beyond the queue were not counted as dropped")
	}
}
