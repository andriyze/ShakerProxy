package syslogcollector

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

func TestFileConfigValidation(t *testing.T) {
	base := DefaultFileConfig()
	if err := base.Validate(); err != nil {
		t.Fatalf("the default (off) config should be valid: %v", err)
	}
	enabledNoSource := base
	enabledNoSource.Enabled = true
	if err := enabledNoSource.Validate(); err == nil {
		t.Fatal("enabling with no allowed source must be rejected")
	}
	enabledNoTransport := base
	enabledNoTransport.Enabled, enabledNoTransport.TCP, enabledNoTransport.UDP, enabledNoTransport.AllowedSources = true, false, false, []string{"192.168.10.1"}
	if err := enabledNoTransport.Validate(); err == nil {
		t.Fatal("enabling with no transport must be rejected")
	}
	badSource := base
	badSource.AllowedSources = []string{"not-an-ip"}
	if err := badSource.Validate(); err == nil {
		t.Fatal("a non-IP allowed source must be rejected")
	}
	good := base
	good.Enabled, good.AllowedSources = true, []string{"192.168.10.1"}
	if err := good.Validate(); err != nil {
		t.Fatalf("a valid enabled config was rejected: %v", err)
	}
	receiver, err := good.ToReceiverConfig()
	if err != nil || !receiver.Enabled || len(receiver.AllowedSources) != 1 {
		t.Fatalf("receiver config: %+v err=%v", receiver, err)
	}
}

func TestLoadConfigMissingFileIsOff(t *testing.T) {
	config, err := LoadConfig(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil || config.Enabled {
		t.Fatalf("missing config should be off: %+v err=%v", config, err)
	}
}

func TestSaveAndLoadConfigRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syslog-config.json")
	config := DefaultFileConfig()
	config.Enabled, config.AllowedSources, config.Revision, config.UpdatedBy = true, []string{"192.168.10.1"}, 2, "admin"
	if err := SaveConfig(path, config); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v err=%v", info.Mode().Perm(), err)
	}
	loaded, err := LoadConfig(path)
	if err != nil || !loaded.Enabled || loaded.Revision != 2 || loaded.UpdatedBy != "admin" || len(loaded.AllowedSources) != 1 {
		t.Fatalf("loaded = %+v err=%v", loaded, err)
	}
}

// The supervisor turns the collector on when the config file enables it and
// off when it is disabled, with no restart of the process.
func TestSupervisorFollowsConfigFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	statusPath := filepath.Join(dir, "status.json")
	sink := &captureSink{}
	supervisor := &Supervisor{
		ConfigPath: configPath, StatusPath: statusPath, Interval: 20 * time.Millisecond,
		NewSink: func() (Sink, error) { return sink, nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = supervisor.Run(ctx) }()

	// Off initially (no config file): status written, nothing listening.
	waitFor(t, func() bool { _, err := os.Stat(statusPath); return err == nil })

	// Enable on a free port.
	enabled := DefaultFileConfig()
	enabled.Enabled, enabled.BindAddress, enabled.AllowedSources = true, "127.0.0.1:0", []string{"127.0.0.1"}
	if err := SaveConfig(configPath, enabled); err != nil {
		t.Fatal(err)
	}
	// The supervisor should pick it up; a status file should report enabled.
	waitFor(t, func() bool {
		raw, err := os.ReadFile(statusPath)
		return err == nil && contains(string(raw), `"enabled":true`)
	})

	// Disable again.
	disabled := enabled
	disabled.Enabled = false
	if err := SaveConfig(configPath, disabled); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		raw, err := os.ReadFile(statusPath)
		return err == nil && contains(string(raw), `"enabled":false`)
	})
	cancel()
	<-done
	_ = ingest.SourceNetworkGear // keep the ingest dependency explicit
}

// A listener that cannot bind is reported, not shown as running, and is
// started again once its port is free.
func TestSupervisorRestartsAListenerThatStopped(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := taken.Addr().String()
	dir := t.TempDir()
	configPath, statusPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "status.json")
	enabled := DefaultFileConfig()
	enabled.Enabled, enabled.BindAddress, enabled.AllowedSources = true, address, []string{"127.0.0.1"}
	if err := SaveConfig(configPath, enabled); err != nil {
		t.Fatal(err)
	}
	supervisor := &Supervisor{ConfigPath: configPath, StatusPath: statusPath, Interval: 20 * time.Millisecond, NewSink: func() (Sink, error) { return &captureSink{}, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = supervisor.Run(ctx) }()
	status := func() Status {
		var status Status
		raw, _ := os.ReadFile(statusPath)
		_ = json.Unmarshal(raw, &status)
		return status
	}
	waitFor(t, func() bool { current := status(); return current.Enabled && !current.Listening && current.Error != "" })
	taken.Close()
	waitFor(t, func() bool { current := status(); return current.Listening && current.Error == "" })
	cancel()
	<-done
}
