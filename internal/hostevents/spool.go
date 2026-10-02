// Package hostevents writes ShakerProxy host events (source HOST) into a
// spool directory that an event forwarder delivers to ingest.
package hostevents

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultQueue           = 4096
	defaultMaxPending      = 20000
	pendingRecountInterval = 10 * time.Second
	dropReportInterval     = 5 * time.Minute
)

// Event is one host event to spool. Encode receives the event ID the file
// is published under.
type Event struct {
	At     time.Time
	Encode func(id string) ([]byte, error)
}

// Spool writes one event file per queued event. Events wait in a bounded
// in-memory queue; when it is full, or when the directory already holds
// MaxPending undelivered events (the forwarder is down), new events are
// dropped and counted, and the count is logged at most every few minutes.
// Queueing never blocks the caller.
type Spool struct {
	Directory  string
	Logger     *slog.Logger
	MaxPending int
	// What the events are, for log messages ("connections").
	Subject string

	queue    chan Event
	dropped  atomic.Uint64
	sequence uint64
	pending  int
}

// New checks that the spool directory exists and is writable.
func New(directory, subject string, logger *slog.Logger) (*Spool, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("host event spool must be an absolute path")
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", directory)
	}
	probe, err := os.CreateTemp(directory, ".probe-")
	if err != nil {
		return nil, fmt.Errorf("host event spool is not writable: %w", err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	return &Spool{Directory: directory, Logger: logger, Subject: subject, queue: make(chan Event, defaultQueue)}, nil
}

// Enqueue queues an event without blocking.
func (s *Spool) Enqueue(event Event) {
	select {
	case s.queue <- event:
	default:
		s.dropped.Add(1)
	}
}

// Dropped returns the number of events dropped and not yet reported.
func (s *Spool) Dropped() uint64 { return s.dropped.Load() }

// Run writes queued events until ctx ends.
func (s *Spool) Run(ctx context.Context) {
	s.removeStaleTemporaryFiles()
	s.pending = s.countPending()
	recount := time.NewTicker(pendingRecountInterval)
	defer recount.Stop()
	report := time.NewTicker(dropReportInterval)
	defer report.Stop()
	var writeErrors uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-recount.C:
			s.pending = s.countPending()
		case <-report.C:
			if dropped := s.dropped.Swap(0); dropped > 0 && s.Logger != nil {
				s.Logger.Warn("host events were not recorded for Traffic; the event spool is full or the event forwarder is not running", "subject", s.Subject, "dropped", dropped, "spool", s.Directory)
			}
		case event := <-s.queue:
			if s.pending >= s.maxPending() {
				s.dropped.Add(1)
				continue
			}
			if err := s.write(event); err != nil {
				s.dropped.Add(1)
				writeErrors++
				if writeErrors == 1 && s.Logger != nil {
					s.Logger.Warn("host event could not be written", "subject", s.Subject, "spool", s.Directory, "error", err)
				}
				continue
			}
			writeErrors = 0
			s.pending++
		}
	}
}

func (s *Spool) maxPending() int {
	if s.MaxPending > 0 {
		return s.MaxPending
	}
	return defaultMaxPending
}

// write publishes one event atomically: the forwarder only picks up
// evt_*.json, so it never sees a partly written file.
func (s *Spool) write(event Event) error {
	s.sequence++
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	// Zero-padded nanoseconds first, so name order is chronological.
	id := fmt.Sprintf("evt_%020d_%08x_%s", event.At.UnixNano(), s.sequence&0xffffffff, hex.EncodeToString(random))
	encoded, err := event.Encode(id)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.Directory, ".tmp-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	// The forwarder container reads the file as another user.
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(s.Directory, id+".json"))
}

func (s *Spool) countPending() int {
	entries, err := os.ReadDir(s.Directory)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "evt_") {
			count++
		}
	}
	return count
}

// removeStaleTemporaryFiles clears files a crash left half written. Another
// writer may share the directory, so only files older than a minute go.
func (s *Spool) removeStaleTemporaryFiles() {
	entries, err := os.ReadDir(s.Directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) > time.Minute {
			_ = os.Remove(filepath.Join(s.Directory, entry.Name()))
		}
	}
}
