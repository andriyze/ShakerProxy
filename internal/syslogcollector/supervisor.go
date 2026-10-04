package syslogcollector

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"time"
)

// SinkFactory builds the sink a receiver delivers to. It is a factory so the
// supervisor can rebuild it if needed; in practice the ingest sink is stable.
type SinkFactory func() (Sink, error)

// Supervisor keeps the running receiver in step with the config file. The
// collector service always runs; it does nothing until the config file enables
// it, and it restarts the listener when the config changes. This keeps the
// control plane simple: control-api writes the config file, and no privileged
// service management is needed to turn the collector on or off.
type Supervisor struct {
	ConfigPath string
	StatusPath string
	Interval   time.Duration
	NewSink    SinkFactory
	Logger     *slog.Logger
}

// Run supervises until ctx is cancelled. A listener that stops on its own
// (its port was taken, a socket failed) is started again on the next tick,
// and its error is in the status until it listens again, so the dashboard
// never shows a dead collector as on.
func (s *Supervisor) Run(ctx context.Context) error {
	logger := s.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	interval := s.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	type running struct {
		receiver *Receiver
		cancel   context.CancelFunc
		done     chan struct{}
		err      error // set before done closes
	}
	var (
		current   Config
		active    *running
		lastError string
	)
	exited := func() bool {
		if active == nil {
			return false
		}
		select {
		case <-active.done:
			return true
		default:
			return false
		}
	}
	stop := func() {
		if active != nil {
			active.cancel()
			<-active.done
			active = nil
		}
	}
	defer stop()
	// fail records why the collector is not listening, logging each new
	// reason once rather than on every retry.
	fail := func(message string, err error) {
		text := message + ": " + err.Error()
		if text != lastError {
			logger.Error(message, "error", err)
		}
		lastError = text
	}

	writeStatus := func() {
		if s.StatusPath == "" {
			return
		}
		status := Status{Enabled: current.Enabled, BindAddress: current.BindAddress, TCP: current.EnableTCP, UDP: current.EnableUDP}
		for _, address := range current.AllowedSources {
			status.AllowedSources = append(status.AllowedSources, address.String())
		}
		if active != nil {
			status.Stats = active.receiver.Stats()
			status.Listening = active.receiver.Listening() && !exited()
		}
		if status.Listening {
			lastError = ""
		}
		status.Error = lastError
		if err := WriteStatusFile(s.StatusPath, status); err != nil {
			logger.Warn("syslog collector status could not be written", "error", err)
		}
	}

	apply := func() {
		fileConfig, err := LoadConfig(s.ConfigPath)
		if err != nil {
			logger.Warn("syslog collector config is invalid; leaving the current state", "error", err)
			return
		}
		next, err := fileConfig.ToReceiverConfig()
		if err != nil {
			logger.Warn("syslog collector config cannot run; leaving the current state", "error", err)
			return
		}
		if exited() {
			stopped := active.err
			if stopped == nil {
				stopped = errors.New("the listener stopped")
			}
			fail("syslog collector listener stopped; starting it again", stopped)
			stop()
		}
		// Nothing changed since the last pass: either already running this
		// config, or already idle. Return before re-logging — in particular do
		// not log "off" on every tick (~17k lines/day while disabled). The main
		// loop still refreshes the status file each tick, so the dashboard keeps
		// seeing a fresh heartbeat.
		if reflect.DeepEqual(next, current) && (active != nil) == next.Enabled {
			return
		}
		stop()
		current = next
		if !next.Enabled {
			lastError = ""
			logger.Info("syslog collector is off")
			writeStatus()
			return
		}
		sink, err := s.NewSink()
		if err != nil {
			fail("syslog collector sink is unavailable", err)
			return
		}
		newReceiver, err := NewReceiver(next, sink, logger)
		if err != nil {
			fail("syslog collector could not start", err)
			return
		}
		runCtx, cancel := context.WithCancel(ctx)
		run := &running{receiver: newReceiver, cancel: cancel, done: make(chan struct{})}
		active = run
		go func() {
			defer close(run.done)
			if runErr := run.receiver.Run(runCtx); runErr != nil && runCtx.Err() == nil {
				run.err = runErr
			}
		}()
		logger.Info("syslog collector starting", "bind", next.BindAddress, "tcp", next.EnableTCP, "udp", next.EnableUDP, "allowed_sources", len(next.AllowedSources))
		writeStatus()
	}

	apply()
	for {
		select {
		case <-ctx.Done():
			writeStatus()
			return nil
		case <-ticker.C:
			apply()
			writeStatus()
		}
	}
}
