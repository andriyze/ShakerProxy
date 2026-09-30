package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayclient"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func connectionTestServer(t *testing.T, logs io.Writer) *Server {
	t.Helper()
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if logs == nil {
		logs = io.Discard
	}
	return NewServer(store, slog.New(slog.NewJSONHandler(logs, nil)))
}

func shortSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "lg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	return filepath.Join(directory, "gw.sock")
}

func serveInBackground(t *testing.T, server *Server, socketPath string) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, socketPath) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if connection, err := net.Dial("unix", socketPath); err == nil {
			connection.Close()
			return cancel, done
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("server exited before listening: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	t.Fatal("server did not start listening")
	return nil, nil
}

func stopServer(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestSlowMethodIsAnsweredAfterRequestReadTimeout(t *testing.T) {
	server := connectionTestServer(t, nil)
	server.readTimeout = 100 * time.Millisecond
	server.dispatcher = func(context.Context, gatewayprotocol.Request) (any, *gatewayprotocol.RPCError) {
		time.Sleep(400 * time.Millisecond)
		return "finished", nil
	}
	socketPath := shortSocketPath(t)
	cancel, done := serveInBackground(t, server, socketPath)
	defer stopServer(t, cancel, done)

	var result string
	if err := (gatewayclient.Client{SocketPath: socketPath}).CallWithTimeout(context.Background(), "ProbeConnectivity", gatewayprotocol.EmptyParams{}, &result, 5*time.Second); err != nil {
		t.Fatalf("slow method lost its response to the request read timeout: %v", err)
	}
	if result != "finished" {
		t.Fatalf("unexpected result %q", result)
	}
}

func TestIdleConnectionIsClosedAfterRequestReadTimeout(t *testing.T) {
	server := connectionTestServer(t, nil)
	server.readTimeout = 100 * time.Millisecond
	socketPath := shortSocketPath(t)
	cancel, done := serveInBackground(t, server, socketPath)
	defer stopServer(t, cancel, done)

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	started := time.Now()
	if _, err := connection.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("idle connection was not closed by the daemon: %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("idle connection outlived the request read timeout")
	}
}

func TestMethodBudgetBoundsDeliveryAndAuditRecordsUndeliveredResponse(t *testing.T) {
	logs := &lockedBuffer{}
	server := connectionTestServer(t, logs)
	server.methodBudget = func(string) time.Duration { return 100 * time.Millisecond }
	release := make(chan struct{})
	server.dispatcher = func(context.Context, gatewayprotocol.Request) (any, *gatewayprotocol.RPCError) {
		<-release
		return map[string]string{"large": strings.Repeat("x", 4<<20)}, nil
	}
	socketPath := shortSocketPath(t)
	cancel, done := serveInBackground(t, server, socketPath)
	defer stopServer(t, cancel, done)

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(connection).Encode(gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "undelivered", Method: "GetManagedState", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	// Never read the response: the daemon's write must hit its method
	// budget and the audit line must say the response was not delivered.
	time.Sleep(200 * time.Millisecond)
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(logs.String(), `"request_id":"undelivered"`) {
		time.Sleep(20 * time.Millisecond)
	}
	connection.Close()
	output := logs.String()
	if !strings.Contains(output, `"request_id":"undelivered"`) || !strings.Contains(output, `"delivered":false`) || !strings.Contains(output, `"success":true`) {
		t.Fatalf("audit did not record the undelivered response: %s", output)
	}
}

func TestServeRefusesLiveSocketAndReplacesStaleSocket(t *testing.T) {
	socketPath := shortSocketPath(t)
	first := connectionTestServer(t, nil)
	cancel, done := serveInBackground(t, first, socketPath)

	second := connectionTestServer(t, nil)
	err := second.Serve(context.Background(), socketPath)
	if err == nil || !strings.Contains(err.Error(), "already serving") {
		t.Fatalf("second daemon replaced a live socket: %v", err)
	}
	if connection, dialErr := net.Dial("unix", socketPath); dialErr != nil {
		t.Fatalf("live daemon socket was removed: %v", dialErr)
	} else {
		connection.Close()
	}
	stopServer(t, cancel, done)
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("daemon did not remove its own socket on shutdown: %v", err)
	}

	stale, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	if info, err := os.Lstat(socketPath); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("stale socket fixture is missing: %v", err)
	}
	third := connectionTestServer(t, nil)
	cancel, done = serveInBackground(t, third, socketPath)
	stopServer(t, cancel, done)
}

func TestServeRefusesNonSocketPath(t *testing.T) {
	socketPath := shortSocketPath(t)
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := connectionTestServer(t, nil).Serve(context.Background(), socketPath); err == nil || !strings.Contains(err.Error(), "non-socket") {
		t.Fatalf("daemon replaced a non-socket path: %v", err)
	}
	if data, err := os.ReadFile(socketPath); err != nil || string(data) != "not a socket" {
		t.Fatalf("non-socket path was modified: %q %v", data, err)
	}
}

func TestShutdownLeavesSocketOwnedByAnotherDaemon(t *testing.T) {
	socketPath := shortSocketPath(t)
	cancel, done := serveInBackground(t, connectionTestServer(t, nil), socketPath)
	// Simulate an operator or replacement daemon taking over the path.
	if err := os.Remove(socketPath); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	stopServer(t, cancel, done)
	if connection, err := net.Dial("unix", socketPath); err != nil {
		t.Fatalf("shutdown removed a socket it no longer owned: %v", err)
	} else {
		connection.Close()
	}
}

func TestManagedStateDegradesWithWarningsInsteadOfFailing(t *testing.T) {
	logs := &lockedBuffer{}
	server := connectionTestServer(t, logs)
	notADirectory := filepath.Join(t.TempDir(), "pcap-root")
	if err := os.WriteFile(notADirectory, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.captures = &capture.Manager{Store: capture.Store{Root: notADirectory}}
	server.store.mu.Lock()
	server.store.state.StagedNetworkPlan = &networkplan.StagedPlan{
		ApplyID: "not-a-valid-apply-id", PlanHash: stateTestPlanHash, Status: string(networktransaction.PhaseConfirmed),
		Plan:        networkplan.Plan{Interfaces: []networkplan.Interface{{StableID: "pci-0000:02:00.0", CurrentName: "enp2s0", Role: networkplan.RoleLab}}},
		Transaction: &networktransaction.Record{Phase: networktransaction.PhaseConfirmed},
	}
	server.store.mu.Unlock()
	server.activation = &NetworkActivation{Store: server.store, Files: networktransaction.FileStore{Root: t.TempDir()}}

	result, rpcErr := server.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "degraded", Method: "GetManagedState", Params: json.RawMessage(`{}`)})
	if rpcErr != nil {
		t.Fatalf("managed state failed wholesale: %+v", rpcErr)
	}
	status, ok := result.(gatewayprotocol.Status)
	if !ok || status.OperatingMode != gatewayprotocol.ModeSetupSafe || len(status.Warnings) != 2 {
		t.Fatalf("degraded status is incomplete: %#v", result)
	}
	if !strings.Contains(status.Warnings[0], "Network") || !strings.Contains(status.Warnings[1], "Capture status") {
		t.Fatalf("warnings do not name the degraded subsystems: %#v", status.Warnings)
	}
	if !reflect.DeepEqual(status.Degraded, []string{gatewayprotocol.DegradedNetworkReconcile, gatewayprotocol.DegradedCaptureList}) {
		t.Fatalf("degraded codes are missing: %#v", status.Degraded)
	}
	if status.LabInterface != "" || status.LabScopePlanHash != "" || status.LabVLANID != nil {
		t.Fatalf("unproven network state still published a lab scope: %#v", status)
	}
	encoded, err := json.Marshal(status)
	if err != nil || !bytes.Contains(encoded, []byte(`"warnings":[`)) {
		t.Fatalf("warnings are not serialized: %s %v", encoded, err)
	}

	server.captures, server.activation = nil, nil
	result, rpcErr = server.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "healthy", Method: "GetManagedState", Params: json.RawMessage(`{}`)})
	if status, ok := result.(gatewayprotocol.Status); rpcErr != nil || !ok || len(status.Warnings) != 0 {
		t.Fatalf("healthy status carried warnings: %#v %+v", result, rpcErr)
	}
}

func TestMethodTimeoutsCoverSlowHostOperations(t *testing.T) {
	if gatewayprotocol.MethodTimeout("ProbeConnectivity") <= 7*time.Second {
		t.Fatal("connectivity probe budget does not exceed its 7 second internal probe")
	}
	for _, method := range []string{"RewritePCAP", "DeletePCAPArtifact", "PreviewPCAPSelection"} {
		if gatewayprotocol.MethodTimeout(method) != gatewayprotocol.MaxMethodTimeout {
			t.Fatalf("%s does not get the two minute PCAP budget", method)
		}
	}
	if gatewayprotocol.MethodTimeout("GetManagedState") != gatewayprotocol.DefaultMethodTimeout {
		t.Fatal("status reads should use the default budget")
	}
}
