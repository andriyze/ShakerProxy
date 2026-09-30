package gatewayprotocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeStrictRejectsUnknownField(t *testing.T) {
	var params SetOperatingModeParams
	err := DecodeStrict(strings.NewReader(`{"mode":"SETUP_SAFE","command":"rm -rf /"}`), &params, MaxRequestBytes)
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestDecodeStrictRejectsMultipleValues(t *testing.T) {
	var params SetOperatingModeParams
	err := DecodeStrict(strings.NewReader(`{"mode":"SETUP_SAFE"} {}`), &params, MaxRequestBytes)
	if err == nil {
		t.Fatal("expected multiple values to fail")
	}
}

func TestDecodeStrictEnforcesLimit(t *testing.T) {
	var params SetOperatingModeParams
	err := DecodeStrict(strings.NewReader(`{"mode":"SETUP_SAFE"}`), &params, 4)
	if err == nil {
		t.Fatal("expected size limit failure")
	}
}

func TestDecodeParamsRejectsUnknownNestedNetworkPlanField(t *testing.T) {
	raw := json.RawMessage(`{"plan":{"schema":1,"name":"x","topology":"TWO_NIC","interfaces":[],"management":{"preserve_active_ssh":true},"ipv4":{"enabled":true,"nat44":true,"client_isolation":true,"shell":"reboot"},"ipv6":{"strategy":"DISABLED"}}}`)
	var params ValidateNetworkPlanParams
	if err := DecodeParams(raw, &params); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("expected nested unknown field rejection, got %v", err)
	}
}
