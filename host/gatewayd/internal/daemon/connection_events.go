package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"shakerproxy.dev/shakerproxy/internal/conntrack"
	"shakerproxy.dev/shakerproxy/internal/hostevents"
)

// DefaultConnectionEventSpool is the host event spool the DNS forwarder
// already writes its lookups to; the host event forwarder delivers both.
const DefaultConnectionEventSpool = "/var/lib/shakerproxy/dns-events/pending"

const (
	connectionScopeRefresh = 10 * time.Second
	connectionRetryDelay   = time.Minute
)

// connectionSource delivers new tracked connections until ctx ends.
type connectionSource interface {
	Run(ctx context.Context, handle func(conntrack.Event)) error
	Dropped() uint64
}

// ConnectionReporter turns every connection a lab device opens through the
// gateway into a Traffic event within about a second, instead of waiting for
// the packet recording to be analyzed. It reads netfilter conntrack creation
// events and records only connections from the confirmed lab network to
// somewhere other than the gateway itself (lookups to the gateway are
// recorded by the DNS forwarder).
type ConnectionReporter struct {
	Store  *StateStore
	Spool  *hostevents.Spool
	Listen func() (connectionSource, error)
	Logger *slog.Logger
	Now    func() time.Time

	scope atomic.Pointer[connectionScope]
}

// connectionScope is the lab traffic worth reporting.
type connectionScope struct {
	labs     []netip.Prefix
	gateways map[netip.Addr]bool
}

// labConnectionScope returns the confirmed routed plan's lab networks and
// gateway addresses, or nil when no lab routes.
func labConnectionScope(store *StateStore) *connectionScope {
	_, plan, ok := confirmedLabPlan(store)
	if !ok {
		return nil
	}
	scope := &connectionScope{gateways: map[netip.Addr]bool{}}
	if prefix, err := netip.ParsePrefix(plan.IPv4.LabCIDR); err == nil {
		scope.labs = append(scope.labs, prefix.Masked())
	}
	if gateway, err := netip.ParseAddr(labGatewayIPv4(plan)); err == nil {
		scope.gateways[gateway] = true
	}
	if prefix, gateway := labIPv6Context(plan); prefix != "" {
		if parsed, err := netip.ParsePrefix(prefix); err == nil {
			scope.labs = append(scope.labs, parsed.Masked())
		}
		if parsed, err := netip.ParseAddr(gateway); err == nil {
			scope.gateways[parsed] = true
		}
	}
	if len(scope.labs) == 0 {
		return nil
	}
	return scope
}

// wants reports a connection a lab device opened to somewhere other than
// the gateway, excluding local-only destinations.
func (s *connectionScope) wants(event conntrack.Event) bool {
	if s == nil {
		return false
	}
	source, destination := event.Source.Addr(), event.Destination.Addr()
	if s.gateways[destination] || s.gateways[source] {
		return false
	}
	// Global unicast includes private addresses and excludes multicast,
	// loopback, link-local and the limited broadcast address.
	if !destination.IsGlobalUnicast() {
		return false
	}
	for _, lab := range s.labs {
		if lab.Contains(source) {
			// The lab's own broadcast address is not a destination.
			if destination.Is4() && lab.Contains(destination) && lab.Bits() < 31 && destination == lastAddress(lab) {
				return false
			}
			return true
		}
	}
	return false
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().As4()
	host := uint32(1)<<(32-prefix.Bits()) - 1
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3]) | host
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// Run reports connections until ctx ends. It keeps retrying when conntrack
// events are unavailable, and logs each distinct problem once.
func (r *ConnectionReporter) Run(ctx context.Context) {
	if r.Store == nil || r.Spool == nil || r.Listen == nil {
		return
	}
	go r.Spool.Run(ctx)
	r.refreshScope()
	go func() {
		ticker := time.NewTicker(connectionScopeRefresh)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.refreshScope()
			}
		}
	}()
	lastProblem := ""
	for ctx.Err() == nil {
		source, err := r.Listen()
		if err == nil {
			if lastProblem != "" {
				r.log(slog.LevelInfo, "live connection reporting resumed")
			}
			lastProblem = ""
			err = source.Run(ctx, r.Handle)
			if dropped := source.Dropped(); dropped > 0 {
				r.log(slog.LevelWarn, "the kernel dropped connection events while the reporter was busy", "overruns", dropped)
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && err.Error() != lastProblem {
			lastProblem = err.Error()
			r.log(slog.LevelWarn, "live connection reporting is unavailable; connections appear in Traffic once the recording is analyzed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(connectionRetryDelay):
		}
	}
}

// Handle queues one tracked connection if it is lab traffic. It never blocks.
func (r *ConnectionReporter) Handle(event conntrack.Event) {
	if !r.scope.Load().wants(event) {
		return
	}
	at := r.now()
	r.Spool.Enqueue(hostevents.Event{At: at, Encode: func(id string) ([]byte, error) {
		return conntrack.EncodeEvent(id, at, event)
	}})
}

func (r *ConnectionReporter) refreshScope() { r.scope.Store(labConnectionScope(r.Store)) }

func (r *ConnectionReporter) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

func (r *ConnectionReporter) log(level slog.Level, message string, attributes ...any) {
	if r.Logger != nil {
		r.Logger.Log(context.Background(), level, message, attributes...)
	}
}

// ReportLabConnections runs a ConnectionReporter writing to spoolPath for
// the daemon's lifetime. "off" or an unusable spool disables it (logged).
func ReportLabConnections(ctx context.Context, store *StateStore, spoolPath string, logger *slog.Logger) {
	if spoolPath == "" || spoolPath == "off" {
		return
	}
	spool, err := hostevents.New(spoolPath, "connections", logger)
	if err != nil {
		if logger != nil {
			logger.Warn("live connection reporting is off: the host event spool is unavailable", "spool", spoolPath, "error", err)
		}
		return
	}
	reporter := &ConnectionReporter{Store: store, Spool: spool, Logger: logger, Listen: func() (connectionSource, error) {
		listener, err := conntrack.Listen()
		if err != nil {
			return nil, err
		}
		return listener, nil
	}}
	reporter.Run(ctx)
}
