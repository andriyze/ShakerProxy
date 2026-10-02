package capture

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng/pcapngtest"
)

// runningFlowFixture records the keep-alive HTTP conversation in a running
// capture whose first closed file holds the first half of the packets and
// the second file the rest.
func runningFlowFixture(t *testing.T) (*Manager, Session, pcapngtest.KeepAliveHTTP, FlowRequest) {
	t.Helper()
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	session.Request.Mode = ModeFull
	session.Request.SnapLength = 0
	session.Request.SegmentSeconds = 30
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	status, err := store.ReadWorkerStatus(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	status.State = StateRunning
	if err := store.WriteWorkerStatus(status); err != nil {
		t.Fatal(err)
	}
	client := netip.MustParseAddrPort("192.168.10.201:41234")
	server := netip.MustParseAddrPort("93.184.216.34:80")
	start := session.StartedAt.Add(25 * time.Second)
	conversation := pcapngtest.NewKeepAliveHTTP(start)
	directory, _ := store.ArtifactDirectory(session.ID)
	split := 5
	files := map[string][]pcapngtest.Packet{
		"capture_00001_20260901120000.pcapng": conversation.Packets[:split],
		"capture_00002_20260901120030.pcapng": conversation.Packets[split:],
	}
	for index, name := range []string{"capture_00001_20260901120000.pcapng", "capture_00002_20260901120030.pcapng"} {
		if err := os.WriteFile(filepath.Join(directory, name), pcapngtest.Conversation(client, server, files[name]), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishClosedSegment(session.ID, name, session.StartedAt.Add(time.Duration(30*(index+1))*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	manager := &Manager{Store: store, Now: func() time.Time { return session.StartedAt.Add(2 * time.Minute) }}
	request := FlowRequest{Schema: FlowRequestSchema, SessionID: session.ID, Client: client.String(), Server: server.String(), At: start.Add(30 * time.Millisecond), BeforeSeconds: 300, AfterSeconds: 120}
	return manager, session, conversation, request
}

func TestReadFlowReassemblesAConnectionAcrossClosedSegmentsOfARunningCapture(t *testing.T) {
	manager, _, conversation, request := runningFlowFixture(t)
	result, err := manager.ReadFlow(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.SegmentsRead != 2 || result.SegmentsMissing != 0 || result.PacketsMatched != len(conversation.Packets) || !result.FromStart || !result.Closed || result.HeadersOnly {
		t.Fatalf("flow summary = %+v", result)
	}
	if !bytes.Equal(result.ClientData, conversation.Client) || !bytes.Equal(result.ServerData, conversation.Server) || result.ClientGap || result.ServerGap {
		t.Fatalf("streams were not reassembled: client=%q server=%d bytes", result.ClientData, len(result.ServerData))
	}
	if result.FirstPacketAt == nil || result.LastPacketAt == nil || !result.LastPacketAt.After(*result.FirstPacketAt) {
		t.Fatalf("packet times = %v %v", result.FirstPacketAt, result.LastPacketAt)
	}
}

func TestReadFlowReportsFilesTheRingRemoved(t *testing.T) {
	manager, session, _, request := runningFlowFixture(t)
	directory, _ := manager.Store.ArtifactDirectory(session.ID)
	if err := os.Remove(filepath.Join(directory, "capture_00001_20260901120000.pcapng")); err != nil {
		t.Fatal(err)
	}
	result, err := manager.ReadFlow(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.SegmentsMissing != 1 || result.SegmentsRead != 1 || result.FromStart || !result.ClientGap && len(result.ClientData) != 0 {
		t.Fatalf("a removed file was not reported: %+v", result)
	}
}

func TestReadFlowFlagsAWindowReachingIntoTheFileStillBeingWritten(t *testing.T) {
	manager, session, _, request := runningFlowFixture(t)
	manager.Controller = &fakeController{active: map[string]bool{session.ID: true}}
	request.At = session.StartedAt.Add(5 * time.Minute)
	request.BeforeSeconds = 10
	result, err := manager.ReadFlow(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OpenSegment || result.PacketsMatched != 0 || result.SegmentsRead != 0 {
		t.Fatalf("open file was not reported: %+v", result)
	}
}

func TestFlowRequestsAreBounded(t *testing.T) {
	_, _, _, request := runningFlowFixture(t)
	for name, mutate := range map[string]func(*FlowRequest){
		"schema":   func(r *FlowRequest) { r.Schema = 2 },
		"session":  func(r *FlowRequest) { r.SessionID = "../etc" },
		"client":   func(r *FlowRequest) { r.Client = "192.168.10.201" },
		"port":     func(r *FlowRequest) { r.Server = "93.184.216.34:0" },
		"time":     func(r *FlowRequest) { r.At = time.Time{} },
		"window":   func(r *FlowRequest) { r.BeforeSeconds = 3600 },
		"negative": func(r *FlowRequest) { r.AfterSeconds = -1 },
	} {
		candidate := request
		mutate(&candidate)
		if candidate.Validate() == nil {
			t.Fatalf("%s: invalid flow request was accepted", name)
		}
	}
}
