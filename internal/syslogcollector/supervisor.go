package syslogcollector

import (
	"context"
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

// Run supervises until ctx is cancelled.
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

	var (
		current   Config
		receiver  *Receiver
		cancelRun context.CancelFunc
		done      chan struct{}
	)
	stop := func() {
		if cancelRun != nil {
			cancelRun()
			<-done
			cancelRun = nil
			receiver = nil
		}
	}
	defer stop()

	writeStatus := func() {
		if s.StatusPath == "" {
			return
		}
		status := Status{Enabled: current.Enabled, BindAddress: current.BindAddress, TCP: current.EnableTCP, UDP: current.EnableUDP}
		for _, address := range current.AllowedSources {
			status.AllowedSources = append(status.AllowedSources, address.String())
		}
		if receiver != nil {
			status.Stats = receiver.Stats()
		}
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
		if receiver != nil && reflect.DeepEqual(next, current) {
			return
		}
		stop()
		current = next
		if !next.Enabled {
			logger.Info("syslog collector is off")
			writeStatus()
			return
		}
		sink, err := s.NewSink()
		if err != nil {
			logger.Error("syslog collector sink is unavailable", "error", err)
			return
		}
		newReceiver, err := NewReceiver(next, sink, logger)
		if err != nil {
			logger.Error("syslog collector could not start", "error", err)
			return
		}
		runCtx, cancel := context.WithCancel(ctx)
		cancelRun = cancel
		receiver = newReceiver
		done = make(chan struct{})
		go func(r *Receiver, c context.Context, finished chan struct{}) {
			defer close(finished)
			if runErr := r.Run(c); runErr != nil && c.Err() == nil {
				logger.Error("syslog collector listener stopped", "error", runErr)
			}
		}(newReceiver, runCtx, done)
		logger.Info("syslog collector listening", "bind", next.BindAddress, "tcp", next.EnableTCP, "udp", next.EnableUDP, "allowed_sources", len(next.AllowedSources))
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
