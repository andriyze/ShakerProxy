package syslogcollector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// DefaultSpool is where the collector leaves events for the
// syslog-event-forwarder container, which delivers them to ingestd over the
// internal network with the ingest token. The collector itself never holds
// the token and never needs a route to ingestd: on an installed appliance
// ingestd is reachable only inside the Compose network.
const DefaultSpool = "/var/lib/shakerproxy/syslog-events/pending"

const (
	defaultSpoolMaxPending = 20000
	spoolRecountInterval   = 10 * time.Second
)

// ErrSpoolFull means the forwarder has fallen behind (or is down) and the
// spool already holds MaxPending events; the event is counted as not
// delivered rather than filling the disk.
var ErrSpoolFull = errors.New("the syslog event spool is full; the forwarder is not keeping up")

// SpoolSink writes each envelope as one file, atomically: the forwarder picks
// up only evt_*.json, so it never sees a partly written event.
type SpoolSink struct {
	Directory  string
	MaxPending int

	mu        sync.Mutex
	pending   int
	countedAt time.Time
	sequence  uint64
}

// NewSpoolSink checks that the spool directory exists and is writable.
func NewSpoolSink(directory string) (*SpoolSink, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("syslog event spool must be an absolute path")
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, fmt.Errorf("syslog event spool: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("syslog event spool %s is not a directory", directory)
	}
	probe, err := os.CreateTemp(directory, ".probe-")
	if err != nil {
		return nil, fmt.Errorf("syslog event spool is not writable: %w", err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	return &SpoolSink{Directory: directory}, nil
}

// Deliver spools one envelope for the forwarder.
func (s *SpoolSink) Deliver(_ context.Context, envelope ingest.Envelope) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	at := time.Now()
	if s.countedAt.IsZero() || at.Sub(s.countedAt) >= spoolRecountInterval {
		s.pending = s.countPending()
		s.countedAt = at
	}
	maxPending := s.MaxPending
	if maxPending <= 0 {
		maxPending = defaultSpoolMaxPending
	}
	if s.pending >= maxPending {
		return ErrSpoolFull
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	s.sequence++
	// Zero-padded nanoseconds first, so name order is arrival order.
	name := fmt.Sprintf("evt_%020d_%08x_%s.json", at.UnixNano(), s.sequence&0xffffffff, hex.EncodeToString(random))
	if err := s.writeFile(name, data); err != nil {
		return err
	}
	s.pending++
	return nil
}

func (s *SpoolSink) writeFile(name string, data []byte) error {
	temporary, err := os.CreateTemp(s.Directory, ".tmp-")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	// The forwarder container reads and removes the file as another user,
	// through the spool directory's group.
	if err := temporary.Chmod(0o640); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(path, filepath.Join(s.Directory, name))
}

func (s *SpoolSink) countPending() int {
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
