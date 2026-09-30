package daemon

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func TestParseSSListenersHandlesResolvedIPv4IPv6AndOwners(t *testing.T) {
	input := "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=408,fd=14))\n" +
		"tcp LISTEN 0 4096 [::]:8443 [::]:* users:((\"caddy\",pid=99,fd=7))\n"
	listeners, err := parseSSListeners(input)
	if err != nil || len(listeners) != 2 {
		t.Fatalf("parse failed: %#v %v", listeners, err)
	}
	if listeners[0].Address != "127.0.0.53" || listeners[0].Port != 53 || listeners[0].Process != "systemd-resolve" {
		t.Fatalf("resolved stub lost: %#v", listeners[0])
	}
	if listeners[1].Address != "::" || listeners[1].Port != 8443 || listeners[1].Process != "caddy" {
		t.Fatalf("IPv6 owner lost: %#v", listeners[1])
	}
}

func TestParseSSListenersRejectsOversizedOutput(t *testing.T) {
	if _, err := parseSSListeners(string(make([]byte, 65<<10))); err == nil {
		t.Fatal("oversized socket inventory accepted")
	}
}

func TestParseProcNetListenersProvidesMinimalImageFallback(t *testing.T) {
	input := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 00000000:0035 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 2\n"
	listeners, err := parseProcNetListeners(input, "tcp", false)
	if err != nil || len(listeners) != 1 {
		t.Fatalf("parse failed: %#v %v", listeners, err)
	}
	if listeners[0].Address != "127.0.0.1" || listeners[0].Port != 8443 || listeners[0].Process != "" {
		t.Fatalf("minimal listener projection changed: %#v", listeners[0])
	}
}

func TestSplitProcNetAddressHandlesIPv6KernelWordOrder(t *testing.T) {
	address, port, ok := splitProcNetAddress("00000000000000000000000001000000:0035", true)
	if !ok || address != "::1" || port != 53 {
		t.Fatalf("unexpected IPv6 socket address: %q %d %t", address, port, ok)
	}
}

func TestResolvedStubIsRecognisedWithoutProcessNames(t *testing.T) {
	for _, listener := range []gatewayprotocol.PortListener{
		{Transport: "udp", Address: "127.0.0.53", Port: 53},
		{Transport: "tcp", Address: "127.0.0.54", Port: 53},
		{Transport: "udp", Address: "127.0.0.53", Port: 53, Process: "systemd-resolve"},
	} {
		if !isResolvedStubListener(listener) {
			t.Fatalf("resolved stub was not recognised: %#v", listener)
		}
	}
	for _, listener := range []gatewayprotocol.PortListener{
		{Transport: "udp", Address: "127.0.0.1", Port: 53},
		{Transport: "udp", Address: "127.0.0.53", Port: 53, Process: "dnsmasq"},
		{Transport: "udp", Address: "0.0.0.0", Port: 53},
		{Transport: "tcp", Address: "127.0.0.53", Port: 853},
	} {
		if isResolvedStubListener(listener) {
			t.Fatalf("listener was mistaken for the resolved stub: %#v", listener)
		}
	}
}

func TestManagementListenerIsRecognisedByItsCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	address, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	directory := t.TempDir()
	authority := filepath.Join(directory, "management-ca.crt")
	if err := os.WriteFile(authority, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	originalPath, originalPort := managementCAPath, managementPort
	t.Cleanup(func() { managementCAPath, managementPort = originalPath, originalPort })
	managementCAPath, managementPort = authority, port

	edge := gatewayprotocol.PortListener{Transport: "tcp", Address: address, Port: port}
	if !isShakerProxyManagementListener(context.Background(), edge) {
		t.Fatal("the edge published by Docker (no visible owner) was not recognised")
	}
	edge.Process = "docker-proxy"
	if !isShakerProxyManagementListener(context.Background(), edge) {
		t.Fatal("the edge behind docker-proxy was not recognised")
	}
	edge.Process = "nginx"
	if isShakerProxyManagementListener(context.Background(), edge) {
		t.Fatal("another program on the management port must stay a conflict")
	}
	managementCAPath = filepath.Join(directory, "missing.crt")
	edge.Process = ""
	if isShakerProxyManagementListener(context.Background(), edge) {
		t.Fatal("a listener must not be trusted without the management CA")
	}
}
