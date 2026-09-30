package capture

import (
	"strings"
	"testing"
)

func TestStartRequestDefaultsAreBounded(t *testing.T) {
	request := (StartRequest{Name: "incident window", Administrator: "admin", IdempotencyKey: "capture-request-0001"}).WithDefaults()
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	if request.Mode != ModeHeaders || request.SnapLength != DefaultHeaderSnapLength || request.MaxFiles != DefaultMaxFiles || request.StopAfterSeconds != DefaultStopAfterSeconds {
		t.Fatalf("unexpected defaults: %#v", request)
	}
}

func TestStartRequestRejectsUnsafeOrUnboundedFields(t *testing.T) {
	base := (StartRequest{Name: "bounded", Administrator: "admin", IdempotencyKey: "capture-request-0002"}).WithDefaults()
	tests := []StartRequest{
		func() StartRequest { value := base; value.Name = "bad\nname"; return value }(),
		func() StartRequest { value := base; value.MaxFiles = 65; return value }(),
		func() StartRequest { value := base; value.SegmentSizeMiB = 1024; value.MaxFiles = 64; return value }(),
		func() StartRequest { value := base; value.StopAfterSeconds = 86401; return value }(),
		func() StartRequest { value := base; value.IdempotencyKey = strings.Repeat("x", 129); return value }(),
	}
	for index, request := range tests {
		if err := request.Validate(); err == nil {
			t.Fatalf("case %d unexpectedly validated", index)
		}
	}
}

func TestSourceRejectsPathLikeInterface(t *testing.T) {
	if err := (Source{InterfaceName: "../eth0", InterfaceStableID: "pci-test"}).Validate(); err == nil {
		t.Fatal("path-like interface unexpectedly validated")
	}
}
