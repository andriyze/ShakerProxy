package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/hostevents"
	"shakerproxy.dev/shakerproxy/internal/nflog"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const (
	// BlockedEventKind is the Traffic event of a refused connection.
	BlockedEventKind = hostevents.BlockedKind
	// DefaultHostEventSpool is shared with shakerproxy-dnsd.
	DefaultHostEventSpool = hostevents.DefaultSpool

	blockedRepeatInterval   = time.Minute
	blockedRecentLimit      = 4096
	blockedMaxPendingEvents = 20000
	blockedListenRetry      = 30 * time.Second
	blockedCopyBytes        = 128
)

// blockReasons maps the NFLOG prefixes of the encrypted DNS block rules
// (trafficpolicy render) to the reason recorded in Traffic.
var blockReasons = map[string]string{
	"SHAKERPROXY_EDNS_DOT":     trafficpolicy.BlockReasonDoT,
	"SHAKERPROXY_EDNS_DOQ":     trafficpolicy.BlockReasonDoQ,
	"SHAKERPROXY_EDNS_DOH_TCP": trafficpolicy.BlockReasonDoHAddress,
	"SHAKERPROXY_EDNS_DOH_UDP": trafficpolicy.BlockReasonDoH3Address,
}

// EncryptedDNSBlockMonitor turns every encrypted-DNS attempt the gateway
// blocks into a Traffic event, so a tester sees that a device tried DNS
// over HTTPS/TLS and fell back. Repeats of the same client, destination
// and reason within a minute are recorded once.
type EncryptedDNSBlockMonitor struct {
	Spool  string
	Logger *slog.Logger
	Listen func(context.Context, uint16, uint32, func(nflog.Packet)) error
	Now    func() time.Time

	mu        sync.Mutex
	recent    map[string]time.Time
	sequence  uint64
	written   int
	pending   int
	dropped   uint64
	lastError string
}

func NewEncryptedDNSBlockMonitor(spool string, logger *slog.Logger) *EncryptedDNSBlockMonitor {
	return &EncryptedDNSBlockMonitor{Spool: spool, Logger: logger, Listen: nflog.Listen}
}

// Run listens until ctx ends, retrying when the log group is unavailable.
func (m *EncryptedDNSBlockMonitor) Run(ctx context.Context) {
	if m == nil || m.Listen == nil {
		return
	}
	for ctx.Err() == nil {
		err := m.Listen(ctx, trafficpolicy.EncryptedDNSLogGroup, blockedCopyBytes, m.Handle)
		if ctx.Err() != nil {
			return
		}
		if err != nil && err.Error() != m.lastError {
			m.lastError = err.Error()
			if m.Logger != nil {
				m.Logger.Warn("blocked encrypted-DNS attempts cannot be reported in Traffic; retrying", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(blockedListenRetry):
		}
	}
}

// Handle records one logged packet.
func (m *EncryptedDNSBlockMonitor) Handle(packet nflog.Packet) {
	reason := blockReasons[strings.TrimSpace(packet.Prefix)]
	if reason == "" {
		return
	}
	flow, ok := nflog.ParseFlow(packet.Payload)
	if !ok || !flow.Source.IsValid() || !flow.Destination.IsValid() {
		return
	}
	at := packet.Time
	if at.IsZero() {
		at = m.now()
	}
	key := fmt.Sprintf("%s|%s|%s|%d|%s", flow.Source, flow.Destination, flow.Protocol, flow.DestinationPort, reason)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recent == nil {
		m.recent = map[string]time.Time{}
	}
	if last, seen := m.recent[key]; seen && at.Sub(last) < blockedRepeatInterval && at.Sub(last) > -blockedRepeatInterval {
		return
	}
	if len(m.recent) >= blockedRecentLimit {
		for candidate, last := range m.recent {
			if at.Sub(last) >= blockedRepeatInterval {
				delete(m.recent, candidate)
			}
		}
		if len(m.recent) >= blockedRecentLimit {
			m.dropped++
			return
		}
	}
	m.recent[key] = at
	if m.written%100 == 0 {
		m.pending = countPendingEvents(m.Spool)
	}
	if m.pending >= blockedMaxPendingEvents {
		m.dropped++
		return
	}
	if err := m.write(at, flow, reason); err != nil {
		m.dropped++
		if m.Logger != nil && err.Error() != m.lastError {
			m.lastError = err.Error()
			m.Logger.Warn("a blocked encrypted-DNS attempt could not be recorded", "error", err)
		}
		return
	}
	m.written++
	m.pending++
}

// write publishes one event atomically: the forwarder only picks up
// evt_*.json, so it never sees a partly written file.
func (m *EncryptedDNSBlockMonitor) write(at time.Time, flow nflog.Flow, reason string) error {
	m.sequence++
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	id := fmt.Sprintf("evt_%020d_%08x_%s", at.UnixNano(), m.sequence&0xffffffff, hex.EncodeToString(random))
	encoded, err := hostevents.BlockedEvent(id, at, flow, reason)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(m.Spool, ".tmp-")
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
	return os.Rename(name, filepath.Join(m.Spool, id+".json"))
}

func countPendingEvents(directory string) int {
	entries, err := os.ReadDir(directory)
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

func (m *EncryptedDNSBlockMonitor) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}
