package mcpserver

import (
	"context"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
)

func (f *fakeBackend) SyslogCollector(context.Context) (agentapi.SyslogCollectorStatus, error) {
	return f.syslog, nil
}

func TestSyslogCollectorReportsStatusReadOnly(t *testing.T) {
	backend := newFakeBackend()
	backend.syslog = agentapi.SyslogCollectorStatus{Available: true, Enabled: true, BindAddress: ":1514", TCP: true, AllowedSources: []string{"192.168.10.1"}}
	backend.syslog.Status = &struct {
		Received   uint64 `json:"received"`
		Parsed     uint64 `json:"parsed"`
		Unparsed   uint64 `json:"unparsed"`
		Delivered  uint64 `json:"delivered"`
		DeliverErr uint64 `json:"deliver_errors"`
		Dropped    uint64 `json:"dropped_rate_limited"`
		Rejected   uint64 `json:"rejected_not_allowed"`
	}{Received: 10, Parsed: 8, Delivered: 8}
	result, _, err := (&Service{backend: backend}).syslogCollector(context.Background(), nil, SyslogCollectorArgs{})
	if err != nil {
		t.Fatal(err)
	}
	var view syslogCollectorResult
	decodeToolResult(t, result, &view)
	if !view.Enabled || view.Received != 10 || view.Delivered != 8 || len(view.AllowedSources) != 1 {
		t.Fatalf("unexpected result: %#v", view)
	}
	if !strings.Contains(view.Summary, "192.168.10.1") || !strings.Contains(view.Summary, "on") {
		t.Fatalf("summary: %q", view.Summary)
	}

	off := newFakeBackend()
	off.syslog = agentapi.SyslogCollectorStatus{Available: true, Enabled: false}
	result, _, err = (&Service{backend: off}).syslogCollector(context.Background(), nil, SyslogCollectorArgs{})
	if err != nil {
		t.Fatal(err)
	}
	var offView syslogCollectorResult
	decodeToolResult(t, result, &offView)
	if offView.Enabled || !strings.Contains(offView.Summary, "off") {
		t.Fatalf("off summary: %#v", offView)
	}
}
