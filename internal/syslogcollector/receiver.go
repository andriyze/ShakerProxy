package syslogcollector

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// Sink delivers a normalized event to the ingest pipeline. The HTTP sink posts
// to ingestd; tests use a fake.
type Sink interface {
	Deliver(context.Context, ingest.Envelope) error
}

// Config controls the receiver. It is disabled by default: a zero Config runs
// nothing. AllowedSources is the set of device addresses whose logs are
// accepted; empty means accept none (fail closed), so a misconfigured
// collector never ingests a stranger's logs. UDP is spoofable, so TCP is
// preferred and UDP is opt-in.
type Config struct {
	Enabled        bool
	BindAddress    string // host:port; defaults to :1514
	EnableTCP      bool
	EnableUDP      bool
	AllowedSources []netip.Addr
	// PerSourceRate and BurstPerSource bound messages per second from one
	// device; GlobalRate and GlobalBurst bound the whole receiver. Zero uses
	// the defaults.
	PerSourceRate  float64
	BurstPerSource int
	GlobalRate     float64
	GlobalBurst    int
}

const (
	defaultBindAddress    = ":1514"
	defaultPerSourceRate  = 200
	defaultBurstPerSource = 400
	defaultGlobalRate     = 2000
	defaultGlobalBurst    = 4000
	maxUDPDatagram        = MaxMessageBytes
	maxConcurrentTCP      = 8
	// deliveryQueueSize bounds the events waiting for the sink. Receiving
	// never waits on delivery: a slow ingestd must not stall the UDP read
	// loop, where the kernel would then drop datagrams unseen.
	deliveryQueueSize = 1024
)

// Stats is a snapshot of what the receiver has seen. It never includes message
// content, only counts and per-source liveness.
type Stats struct {
	Received   uint64 `json:"received"`
	Parsed     uint64 `json:"parsed"`
	Unparsed   uint64 `json:"unparsed"`
	Delivered  uint64 `json:"delivered"`
	DeliverErr uint64 `json:"deliver_errors"`
	Dropped    uint64 `json:"dropped_rate_limited"`
	Rejected   uint64 `json:"rejected_not_allowed"`
	Oversize   uint64 `json:"oversize"`
	// Backlog counts events dropped because the delivery queue was full.
	Backlog   uint64              `json:"dropped_backlog"`
	PerSource map[string]SourceSt `json:"per_source,omitempty"`
}

// SourceSt is per-device liveness, keyed by device address.
type SourceSt struct {
	Received uint64    `json:"received"`
	Parsed   uint64    `json:"parsed"`
	LastSeen time.Time `json:"last_seen"`
}

// Receiver listens for syslog and delivers recognized events. It is safe for
// concurrent use and must be stopped by cancelling the context passed to Run.
type Receiver struct {
	config  Config
	sink    Sink
	logger  *slog.Logger
	allowed map[netip.Addr]bool
	global  *bucket
	now     func() time.Time

	queue     chan ingest.Envelope
	delivery  sync.Once
	listening atomic.Bool

	mu      sync.Mutex
	stats   Stats
	buckets map[netip.Addr]*bucket
	sources map[netip.Addr]*SourceSt
}

// NewReceiver builds a receiver. It returns an error for an invalid config so
// a bad setting never silently disables collection.
func NewReceiver(config Config, sink Sink, logger *slog.Logger) (*Receiver, error) {
	if sink == nil {
		return nil, errors.New("syslog collector requires a sink")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if config.BindAddress == "" {
		config.BindAddress = defaultBindAddress
	}
	if !config.EnableTCP && !config.EnableUDP {
		config.EnableTCP = true
	}
	allowed := map[netip.Addr]bool{}
	for _, address := range config.AllowedSources {
		if address.IsValid() {
			allowed[address.Unmap()] = true
		}
	}
	rate := orDefault(config.GlobalRate, defaultGlobalRate)
	burst := orDefaultInt(config.GlobalBurst, defaultGlobalBurst)
	return &Receiver{
		config:  config,
		sink:    sink,
		logger:  logger,
		allowed: allowed,
		global:  newBucket(rate, burst),
		now:     time.Now,
		queue:   make(chan ingest.Envelope, deliveryQueueSize),
		buckets: map[netip.Addr]*bucket{},
		sources: map[netip.Addr]*SourceSt{},
	}, nil
}

// Listening reports whether the receiver holds its sockets.
func (r *Receiver) Listening() bool { return r.listening.Load() }

// Run listens until ctx is cancelled. It does nothing when the config is
// disabled, so enabling is always an explicit choice. Every socket is bound
// before any is served: if one cannot be, the others are closed and the
// error returned, and when one stops serving the others stop too, so the
// caller restarts a whole receiver, never half of one.
func (r *Receiver) Run(ctx context.Context) error {
	if !r.config.Enabled {
		return nil
	}
	if len(r.allowed) == 0 {
		r.logger.Warn("syslog collector has no allowed sources; it will accept nothing")
	}
	var listener net.Listener
	var packet net.PacketConn
	if r.config.EnableTCP {
		bound, err := net.Listen("tcp", r.config.BindAddress)
		if err != nil {
			return fmt.Errorf("listen on TCP %s: %w", r.config.BindAddress, err)
		}
		listener = bound
	}
	if r.config.EnableUDP {
		bound, err := net.ListenPacket("udp", r.config.BindAddress)
		if err != nil {
			if listener != nil {
				listener.Close()
			}
			return fmt.Errorf("listen on UDP %s: %w", r.config.BindAddress, err)
		}
		packet = bound
	}
	r.listening.Store(true)
	defer r.listening.Store(false)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var group sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	fail := func(err error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
		cancel()
	}
	if listener != nil {
		group.Add(1)
		go func() {
			defer group.Done()
			if serveErr := r.serveTCP(runCtx, listener); serveErr != nil && runCtx.Err() == nil {
				fail(serveErr)
			}
		}()
	}
	if packet != nil {
		group.Add(1)
		go func() {
			defer group.Done()
			if serveErr := r.serveUDP(runCtx, packet); serveErr != nil && runCtx.Err() == nil {
				fail(serveErr)
			}
		}()
	}
	group.Wait()
	if firstErr == nil && ctx.Err() == nil {
		firstErr = errors.New("the syslog listener stopped")
	}
	return firstErr
}

// startDelivery runs the one delivery worker, which sends queued events to
// the sink in order until ctx ends.
func (r *Receiver) startDelivery(ctx context.Context) {
	r.delivery.Do(func() {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case envelope := <-r.queue:
					r.deliver(ctx, envelope)
				}
			}
		}()
	})
}

func (r *Receiver) deliver(ctx context.Context, envelope ingest.Envelope) {
	if err := r.sink.Deliver(ctx, envelope); err != nil {
		r.count(func(s *Stats) { s.DeliverErr++ })
		return
	}
	r.count(func(s *Stats) { s.Delivered++ })
}

// drain delivers what is queued now, on the caller's goroutine.
func (r *Receiver) drain(ctx context.Context) {
	for {
		select {
		case envelope := <-r.queue:
			r.deliver(ctx, envelope)
		default:
			return
		}
	}
}

func (r *Receiver) serveTCP(ctx context.Context, listener net.Listener) error {
	defer listener.Close()
	r.startDelivery(ctx)
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	semaphore := make(chan struct{}, maxConcurrentTCP)
	var conns sync.WaitGroup
	for {
		conn, err := listener.Accept()
		if err != nil {
			conns.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !r.allow(conn.RemoteAddr()) {
			r.count(func(s *Stats) { s.Rejected++ })
			conn.Close()
			continue
		}
		select {
		case semaphore <- struct{}{}:
		default:
			// Too many connections: shed the newest rather than queue.
			conn.Close()
			continue
		}
		conns.Add(1)
		go func() {
			defer conns.Done()
			defer func() { <-semaphore }()
			r.handleTCP(ctx, conn)
		}()
	}
}

func (r *Receiver) handleTCP(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	// An idle sender would hold the read for its whole deadline; closing
	// the connection on shutdown ends it at once.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	source := addrOf(conn.RemoteAddr())
	reader := bufio.NewReaderSize(conn, 16<<10)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(r.now().Add(5 * time.Minute))
		frame, err := ReadFrame(reader)
		if err != nil {
			if errors.Is(err, errFrameTooLarge) {
				r.count(func(s *Stats) { s.Oversize++ })
				continue
			}
			return
		}
		r.ingest(ctx, source, frame)
	}
}

func (r *Receiver) serveUDP(ctx context.Context, packet net.PacketConn) error {
	defer packet.Close()
	r.startDelivery(ctx)
	go func() {
		<-ctx.Done()
		packet.Close()
	}()
	buffer := make([]byte, maxUDPDatagram)
	for {
		if ctx.Err() != nil {
			return nil
		}
		_ = packet.SetReadDeadline(r.now().Add(time.Second))
		n, addr, err := packet.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		source := addrOf(addr)
		if !r.allowAddr(source) {
			r.count(func(s *Stats) { s.Rejected++ })
			continue
		}
		frame := make([]byte, n)
		copy(frame, buffer[:n])
		r.ingest(ctx, source, frame)
	}
}

// ingest applies rate limiting, parses one message, and delivers it. Content
// is only ever parsed into bounded fields; it is never interpreted.
func (r *Receiver) ingest(ctx context.Context, source netip.Addr, frame []byte) {
	if len(frame) > MaxMessageBytes {
		r.count(func(s *Stats) { s.Oversize++ })
		return
	}
	if !r.global.allow(r.now()) || !r.sourceBucket(source).allow(r.now()) {
		r.count(func(s *Stats) { s.Dropped++ })
		return
	}
	now := r.now().UTC()
	message := ParseSyslog(frame, now)
	record, ok := Parse(message)
	r.mu.Lock()
	r.stats.Received++
	entry := r.sources[source]
	if entry == nil {
		entry = &SourceSt{}
		r.sources[source] = entry
	}
	entry.Received++
	entry.LastSeen = now
	if ok {
		r.stats.Parsed++
		entry.Parsed++
	} else {
		r.stats.Unparsed++
	}
	r.mu.Unlock()
	if !ok {
		return
	}
	timestamp := message.Timestamp
	if timestamp.IsZero() || timestamp.Year() < 2000 || timestamp.Year() > 3000 {
		timestamp = now
	}
	envelope, err := Normalize(record, source.String(), timestamp)
	if err != nil {
		r.count(func(s *Stats) { s.Unparsed++ })
		return
	}
	select {
	case r.queue <- envelope:
	default:
		r.count(func(s *Stats) { s.Backlog++ })
	}
}

// Stats returns a snapshot, including per-source liveness.
func (r *Receiver) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshot := r.stats
	snapshot.PerSource = map[string]SourceSt{}
	for address, entry := range r.sources {
		snapshot.PerSource[address.String()] = *entry
	}
	return snapshot
}

func (r *Receiver) allow(addr net.Addr) bool { return r.allowAddr(addrOf(addr)) }

func (r *Receiver) allowAddr(address netip.Addr) bool {
	return address.IsValid() && r.allowed[address.Unmap()]
}

func (r *Receiver) sourceBucket(source netip.Addr) *bucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.buckets[source]; existing != nil {
		return existing
	}
	created := newBucket(orDefault(r.config.PerSourceRate, defaultPerSourceRate), orDefaultInt(r.config.BurstPerSource, defaultBurstPerSource))
	r.buckets[source] = created
	return created
}

func (r *Receiver) count(change func(*Stats)) {
	r.mu.Lock()
	change(&r.stats)
	r.mu.Unlock()
}

func addrOf(addr net.Addr) netip.Addr {
	switch value := addr.(type) {
	case *net.TCPAddr:
		if a, ok := netip.AddrFromSlice(value.IP); ok {
			return a.Unmap()
		}
	case *net.UDPAddr:
		if a, ok := netip.AddrFromSlice(value.IP); ok {
			return a.Unmap()
		}
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a.Unmap()
		}
	}
	return netip.Addr{}
}

func orDefault(value, fallback float64) float64 {
	if value <= 0 {
		return fallback
	}
	return value
}

func orDefaultInt(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
