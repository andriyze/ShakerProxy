package syslogcollector

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingHandler counts log records whose message contains a substring.
type countingHandler struct {
	mu     sync.Mutex
	substr string
	count  int
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *countingHandler) WithGroup(string) slog.Handler            { return h }
func (h *countingHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if strings.Contains(record.Message, h.substr) {
		h.count++
	}
	return nil
}

// A disabled collector must not log "off" on every supervision tick; it did,
// about 17k journal lines a day on a real appliance.
func TestSupervisorDisabledLogsOffAtMostOnce(t *testing.T) {
	handler := &countingHandler{substr: "syslog collector is off"}
	supervisor := &Supervisor{
		// A missing config file means the collector is off, which is the
		// normal state before anyone enables it.
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
		StatusPath: filepath.Join(t.TempDir(), "status.json"),
		Interval:   5 * time.Millisecond,
		NewSink:    func() (Sink, error) { return nil, nil }, // never called while off
		Logger:     slog.New(handler),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := supervisor.Run(ctx); err != nil {
		t.Fatalf("supervisor returned %v", err)
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.count > 1 {
		t.Fatalf("logged %q %d times over ~30 ticks; want at most once", handler.substr, handler.count)
	}
	// The status file is still refreshed every tick, so the dashboard sees a
	// fresh heartbeat even though nothing is logged.
	if info, err := os.Stat(supervisor.StatusPath); err != nil || info.Size() == 0 {
		t.Fatalf("status file was not refreshed while off: %v", err)
	}
}
