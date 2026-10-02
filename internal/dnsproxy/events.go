package dnsproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	// LookupEventKind is the ingest kind of a forwarder lookup. The event
	// forwarder accepts only this kind from the DNS spool.
	LookupEventKind          = "shakerproxy.dns"
	lookupEventSourceVersion = "shakerproxy-dnsd-1"
	lookupEventParserVersion = "shakerproxy-dns-v1"

	// DefaultEventSpool is where dnsd leaves lookup events for the
	// dns-event-forwarder container, which delivers them to ingest.
	DefaultEventSpool       = "/var/lib/shakerproxy/dns-events/pending"
	defaultEventQueue       = 4096
	defaultMaxPendingEvents = 20000
	pendingRecountInterval  = 10 * time.Second
	dropReportInterval      = 5 * time.Minute
)

// SpoolRecorder writes one ingest event file per answered lookup. Lookups
// wait in a bounded in-memory queue; when it is full, or when the spool
// already holds MaxPending undelivered events (the forwarder is down), new
// lookups are dropped and counted, and the count is logged at most every
// few minutes. Recording never slows an answer.
type SpoolRecorder struct {
	Directory  string
	Logger     *slog.Logger
	MaxPending int

	queue    chan Lookup
	dropped  atomic.Uint64
	sequence uint64
	pending  int
}

// NewSpoolRecorder checks that the spool directory exists and is writable.
func NewSpoolRecorder(directory string, logger *slog.Logger) (*SpoolRecorder, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("DNS event spool must be an absolute path")
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
		return nil, fmt.Errorf("DNS event spool is not writable: %w", err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	return &SpoolRecorder{Directory: directory, Logger: logger, queue: make(chan Lookup, defaultEventQueue)}, nil
}

// ObserveLookup queues a lookup without blocking.
func (r *SpoolRecorder) ObserveLookup(lookup Lookup) {
	select {
	case r.queue <- lookup:
	default:
		r.dropped.Add(1)
	}
}

// Run writes queued lookups until ctx ends.
func (r *SpoolRecorder) Run(ctx context.Context) {
	r.removeStaleTemporaryFiles()
	r.pending = r.countPending()
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
			r.pending = r.countPending()
		case <-report.C:
			if dropped := r.dropped.Swap(0); dropped > 0 && r.Logger != nil {
				r.Logger.Warn("DNS lookups were not recorded for Traffic; the event spool is full or the event forwarder is not running", "dropped", dropped, "spool", r.Directory)
			}
		case lookup := <-r.queue:
			if r.pending >= r.maxPending() {
				r.dropped.Add(1)
				continue
			}
			if err := r.write(lookup); err != nil {
				r.dropped.Add(1)
				writeErrors++
				if writeErrors == 1 && r.Logger != nil {
					r.Logger.Warn("DNS lookup event could not be written", "spool", r.Directory, "error", err)
				}
				continue
			}
			writeErrors = 0
			r.pending++
		}
	}
}

func (r *SpoolRecorder) maxPending() int {
	if r.MaxPending > 0 {
		return r.MaxPending
	}
	return defaultMaxPendingEvents
}

// write publishes one event atomically: the forwarder only picks up
// evt_*.json, so it never sees a partly written file.
func (r *SpoolRecorder) write(lookup Lookup) error {
	r.sequence++
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	// Zero-padded nanoseconds first, so name order is chronological.
	id := fmt.Sprintf("evt_%020d_%08x_%s", lookup.At.UnixNano(), r.sequence&0xffffffff, hex.EncodeToString(random))
	encoded, err := LookupEvent(id, lookup)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(r.Directory, ".tmp-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	// The forwarder container reads the file as another user; the spool
	// directory itself is closed to everyone else.
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
	return os.Rename(name, filepath.Join(r.Directory, id+".json"))
}

func (r *SpoolRecorder) countPending() int {
	entries, err := os.ReadDir(r.Directory)
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

// removeStaleTemporaryFiles clears files a crash left half written.
func (r *SpoolRecorder) removeStaleTemporaryFiles() {
	entries, err := os.ReadDir(r.Directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			_ = os.Remove(filepath.Join(r.Directory, entry.Name()))
		}
	}
}

type lookupEventEnvelope struct {
	Schema        int             `json:"schema"`
	EventID       string          `json:"event_id"`
	Source        string          `json:"source"`
	Kind          string          `json:"kind"`
	OccurredAt    time.Time       `json:"occurred_at"`
	SourceVersion string          `json:"source_version"`
	ParserVersion string          `json:"parser_version"`
	Confidence    int             `json:"confidence"`
	Payload       json.RawMessage `json:"payload"`
}

type lookupEventPayload struct {
	SourceIP        string        `json:"source_ip"`
	SourcePort      int           `json:"source_port,omitempty"`
	DestinationPort int           `json:"destination_port"`
	Protocol        string        `json:"protocol"`
	Service         string        `json:"service"`
	Query           string        `json:"query"`
	QueryType       string        `json:"query_type"`
	ResponseCode    string        `json:"response_code,omitempty"`
	AnswerCount     int           `json:"answer_count"`
	Answers         []lookupEntry `json:"answers"`
	Blocked         bool          `json:"blocked"`
	BlockedDomain   string        `json:"blocked_domain,omitempty"`
}

type lookupEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data,omitempty"`
}

// LookupEvent encodes a lookup as an ingest event envelope (source HOST,
// kind shakerproxy.dns). The device is attributed by ingest from the client
// address, the same way as for analyzer events.
func LookupEvent(id string, lookup Lookup) ([]byte, error) {
	if !lookup.Client.Addr().IsValid() || lookup.Name == "" && lookup.Type == "" {
		return nil, errors.New("DNS lookup has no client or question")
	}
	name := lookup.Name
	if name == "" {
		name = "."
	}
	answers := make([]lookupEntry, 0, len(lookup.Answers))
	for _, answer := range lookup.Answers {
		answers = append(answers, lookupEntry{Name: answer.Name, Type: answer.Type, TTL: answer.TTL, Data: answer.Data})
	}
	payload, err := json.Marshal(lookupEventPayload{
		SourceIP: lookup.Client.Addr().String(), SourcePort: int(lookup.Client.Port()), DestinationPort: 53,
		Protocol: lookup.Transport, Service: "dns", Query: name, QueryType: lookup.Type, ResponseCode: lookup.Rcode,
		AnswerCount: lookup.AnswerCount, Answers: answers, Blocked: lookup.Blocked, BlockedDomain: lookup.BlockedDomain,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(lookupEventEnvelope{
		Schema: 1, EventID: id, Source: "HOST", Kind: LookupEventKind, OccurredAt: lookup.At.UTC(),
		SourceVersion: lookupEventSourceVersion, ParserVersion: lookupEventParserVersion, Confidence: 100, Payload: payload,
	})
}
