package ingest

import (
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func TestCompileEventFilterUsesOnlyTypedColumnsAndArguments(t *testing.T) {
	filter, err := querylang.Parse(`source:SURICATA (dst.ip:1.1.1.0/24 OR dst.port:>=443) NOT service:* protocol:t*`)
	if err != nil {
		t.Fatal(err)
	}
	args := []any{"existing"}
	statement, err := compileEventFilter(filter.Root, nil, nil, time.Time{}, false, &args)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"source = $2", "destination_ip <<= $3::cidr", "destination_port >= $4", "NOT service IS NOT NULL", "protocol LIKE $5 ESCAPE E'\\\\'"} {
		if !strings.Contains(statement, required) {
			t.Fatalf("compiled filter %q omitted %q", statement, required)
		}
	}
	if len(args) != 5 || args[1] != "SURICATA" || args[2] != "1.1.1.0/24" || args[3] != int64(443) || args[4] != "t%" {
		t.Fatalf("unexpected bound arguments: %#v", args)
	}
}

func TestCompileEventFilterRejectsForgedAST(t *testing.T) {
	args := []any{}
	forged := &querylang.Node{Type: querylang.NodePredicate, Predicate: &querylang.Predicate{Field: "payload", Operator: querylang.OperatorEqual, Value: "secret"}}
	if _, err := compileEventFilter(forged, nil, nil, time.Time{}, false, &args); err == nil || len(args) != 0 {
		t.Fatalf("forged AST was accepted: %#v %v", args, err)
	}
}

func TestCompileEventFilterBindsResolvedDeviceNames(t *testing.T) {
	filter, err := querylang.Parse(`device.name:"Bench Camera" OR NOT device.name:"Missing"`)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device-0123456789abcdef0123456789abcdef"
	args := []any{}
	statement, err := compileEventFilter(filter.Root, map[string][]string{"Bench Camera": {deviceID}, "Missing": {}}, nil, time.Time{}, false, &args)
	if err != nil || !strings.Contains(statement, "COALESCE(device_id = ANY($1::text[]), FALSE)") || !strings.Contains(statement, "NOT FALSE") || len(args) != 1 {
		t.Fatalf("unexpected device-name predicate: %q %#v %v", statement, args, err)
	}
	ids, ok := args[0].([]string)
	if !ok || len(ids) != 1 || ids[0] != deviceID {
		t.Fatalf("device IDs were not bound as an array: %#v", args)
	}
}

func TestCompileEventFilterBindsResolvedDeviceTags(t *testing.T) {
	filter, err := querylang.Parse(`device.tag:camera AND device.tag!=retired`)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device-0123456789abcdef0123456789abcdef"
	args := []any{}
	statement, err := compileEventFilter(filter.Root, nil, map[string][]string{"camera": {deviceID}, "retired": {}}, time.Time{}, false, &args)
	if err != nil || !strings.Contains(statement, "COALESCE(device_id = ANY($1::text[]), FALSE)") || !strings.Contains(statement, "AND TRUE") || len(args) != 1 {
		t.Fatalf("unexpected device-tag predicate: %q %#v %v", statement, args, err)
	}
}

func TestCompileEventFilterBindsFrozenRelativeAndAbsoluteTime(t *testing.T) {
	filter, err := querylang.Parse(`time:last_15m AND time<2026-09-01T13:00:00Z`)
	if err != nil {
		t.Fatal(err)
	}
	anchor := time.Date(2026, 9, 1, 12, 30, 0, 0, time.UTC)
	args := []any{}
	statement, err := compileEventFilter(filter.Root, nil, nil, anchor, true, &args)
	if err != nil || !strings.Contains(statement, "occurred_at >= $1") || !strings.Contains(statement, "occurred_at <= $2") || !strings.Contains(statement, "occurred_at < $3") || len(args) != 3 {
		t.Fatalf("unexpected time predicate: %q %#v %v", statement, args, err)
	}
	if lower, ok := args[0].(time.Time); !ok || !lower.Equal(anchor.Add(-15*time.Minute)) || !args[1].(time.Time).Equal(anchor) || !args[2].(time.Time).Equal(time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)) {
		t.Fatalf("time arguments were not frozen and bound: %#v", args)
	}
	args = nil
	if _, err := compileEventFilter(filter.Root.Children[0], nil, nil, time.Time{}, false, &args); err == nil || len(args) != 0 {
		t.Fatalf("relative time compiled without an anchor: %#v %v", args, err)
	}
}
