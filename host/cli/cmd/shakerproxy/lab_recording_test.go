package main

import (
	"encoding/json"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func TestCaptureAutoShowsAndChangesLabRecording(t *testing.T) {
	enabled := true
	_, socket := startFakeGateway(t, func(method string, params json.RawMessage) (any, *gatewayprotocol.RPCError) {
		switch method {
		case "GetManagedState":
			return gatewayprotocol.Status{CaptureAvailable: true, LabRecording: &gatewayprotocol.LabRecordingStatus{Enabled: enabled, Recording: enabled, SessionID: "capture-0123456789abcdef0123456789abcdef"}}, nil
		case "SetLabRecording":
			var decoded gatewayprotocol.SetLabRecordingParams
			_ = json.Unmarshal(params, &decoded)
			enabled = decoded.Enabled
			return gatewayprotocol.LabRecordingStatus{Enabled: enabled, Recording: enabled}, nil
		}
		return nil, &gatewayprotocol.RPCError{Code: -32601, Message: "method not found"}
	})
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "capture", "auto", "--socket", socket)
	if code != exitOK || !strings.Contains(stdout, "recording lab traffic") || !strings.Contains(stdout, "capture-0123456789abcdef0123456789abcdef") {
		t.Fatalf("capture auto (%d): %s %s", code, stdout, stderr)
	}
	code, stdout, stderr = runCLI(t, c, "capture", "auto", "off", "--socket", socket)
	if code != exitOK || enabled || !strings.Contains(stdout, "off. Turn it on: sudo shakerproxy capture auto on") {
		t.Fatalf("capture auto off (%d): %s %s", code, stdout, stderr)
	}
	code, stdout, stderr = runCLI(t, c, "status", "--socket", socket)
	if code != exitOK || !strings.Contains(stdout, "capture auto on") {
		t.Fatalf("status does not show that lab recording is off (%d): %s %s", code, stdout, stderr)
	}
	if code, _, stderr := runCLI(t, c, "capture", "auto", "maybe", "--socket", socket); code == exitOK || !strings.Contains(stderr, "on or off") {
		t.Fatalf("capture auto accepted a bad value (%d): %s", code, stderr)
	}
}
