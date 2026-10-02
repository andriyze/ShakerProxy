package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

func TestAddingAVPNDeviceNamesItsAddressAndReturnsTheConfigOnce(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	peer := gatewayprotocol.VPNPeerStatus{ID: "vpn-0123456789abcdef", Name: "Pixel", IPv4: "10.89.0.2", IPv6: "fd12:3456:789a:1::2", CreatedAt: time.Now().UTC()}
	config := "[Interface]\nPrivateKey = secret\n"
	var deviceID string
	requests := startGatewaySequenceStub(t, socketPath,
		gatewayprotocol.VPNPeerConfig{Peer: peer, Config: config, FileName: "pixel.conf"},
		func(request gatewayprotocol.Request) any {
			var params gatewayprotocol.SetVPNPeerDeviceParams
			_ = json.Unmarshal(request.Params, &params)
			deviceID = params.DeviceID
			named := peer
			named.DeviceID = params.DeviceID
			return named
		},
		gatewayprotocol.VPNPeerStatus{ID: peer.ID, Name: "Pixel"},
	)
	server, session := configuredAPIServer(t, socketPath)
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json")}

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPost, "/api/v1/vpn/devices", `{"name":"Pixel","password":"`+activationTestPassword+`"}`, session, ""))
	var added addVPNDeviceResponse
	if recorder.Code != http.StatusCreated || json.Unmarshal(recorder.Body.Bytes(), &added) != nil {
		t.Fatalf("POST returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if added.Config != config || added.DeviceName != "Pixel (VPN)" || added.DeviceID == "" || added.DeviceID != deviceID || added.Peer.DeviceID != deviceID || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("added = %+v headers %v", added, recorder.Header())
	}
	device, err := server.inventory.Get(deviceID)
	if err != nil || device.PinnedAddress != "10.89.0.2" || device.FriendlyName != "Pixel (VPN)" {
		t.Fatalf("inventory device = %+v, %v", device, err)
	}
	for _, want := range []string{"AddVPNPeer", "SetVPNPeerDevice"} {
		rpc := <-requests
		if rpc.Method != want || strings.Contains(string(rpc.Params), activationTestPassword) {
			t.Fatalf("got RPC %q %s, want %q", rpc.Method, rpc.Params, want)
		}
	}

	// Revoking keeps the device's name in Devices.
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodDelete, "/api/v1/vpn/devices/"+peer.ID, `{}`, session, ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("DELETE returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if rpc := <-requests; rpc.Method != "RevokeVPNPeer" {
		t.Fatalf("got RPC %q", rpc.Method)
	}
	if device, err := server.inventory.Get(deviceID); err != nil || device.PinnedAddress != "10.89.0.2" {
		t.Fatalf("revoking dropped the device's history: %+v %v", device, err)
	}

	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodDelete, "/api/v1/vpn/devices/not-a-peer", `{}`, session, ""))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("an invalid peer ID returned %d", recorder.Code)
	}
}
