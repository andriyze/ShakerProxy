package gatewayclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func TestClientRejectsUnboundedTimeouts(t *testing.T) {
	client := Client{SocketPath: filepath.Join(t.TempDir(), "absent.sock")}
	for _, timeout := range []time.Duration{0, 500 * time.Millisecond, gatewayprotocol.MaxMethodTimeout + time.Second} {
		err := client.CallWithTimeout(context.Background(), "GetManagedState", gatewayprotocol.EmptyParams{}, nil, timeout)
		if err == nil || !strings.Contains(err.Error(), "timeout is invalid") {
			t.Fatalf("timeout %s was accepted: %v", timeout, err)
		}
	}
	err := client.Call(context.Background(), "RewritePCAP", gatewayprotocol.EmptyParams{}, nil)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("two minute PCAP budget was rejected or the dial error lost its cause: %v", err)
	}
}

func TestClientRejectsOversizedGatewayResponse(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listener.Close()
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request gatewayprotocol.Request
		if json.NewDecoder(connection).Decode(&request) != nil {
			return
		}
		_ = json.NewEncoder(connection).Encode(gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: request.ID, Result: strings.Repeat("x", gatewayprotocol.MaxResponseBytes)})
	}()
	var result string
	err = (Client{SocketPath: socketPath}).Call(context.Background(), "OversizedTest", gatewayprotocol.EmptyParams{}, &result)
	if err == nil {
		t.Fatal("client accepted an oversized privileged response")
	}
}
