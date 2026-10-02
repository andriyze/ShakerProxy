package dnsproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv6"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const (
	// DefaultBind listens on every address of both families. The gateway's
	// fixed INPUT rules keep the port reachable only from loopback and the
	// lab segment.
	DefaultBind         = ":1053"
	defaultTimeout      = 4 * time.Second
	maxParallelUpstream = 3
	upstreamDownFor     = 30 * time.Second
	blockLogInterval    = time.Minute
	maxBlockLogEntries  = 4096
)

type Server struct {
	Bind          string
	Provider      RuntimeProvider
	Logger        *slog.Logger
	Timeout       time.Duration
	MaxConcurrent int
	// HedgeDelay is how long one upstream may stay silent before the next
	// is queried in parallel. Defaults to a quarter of Timeout, at most 500ms.
	HedgeDelay time.Duration
	// Observer, when set, receives every answered lab query after its answer
	// was sent.
	Observer     LookupObserver
	nextUpstream atomic.Uint64
	health       upstreamHealth
	blockLog     blockLogLimiter
}

func (s *Server) Serve(ctx context.Context) error {
	return s.serve(ctx, nil)
}

// serve optionally reports the bound UDP and TCP addresses (tests bind :0).
func (s *Server) serve(ctx context.Context, ready chan<- [2]net.Addr) error {
	if s.Provider == nil {
		return errors.New("DNS runtime provider is required")
	}
	if s.Bind == "" {
		s.Bind = DefaultBind
	}
	if s.Timeout <= 0 {
		s.Timeout = defaultTimeout
	}
	if s.MaxConcurrent <= 0 {
		s.MaxConcurrent = 256
	}
	address, err := net.ResolveUDPAddr("udp", s.Bind)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", address)
	if err != nil {
		return err
	}
	defer udp.Close()
	tcpBind := s.Bind
	if address.Port == 0 {
		tcpBind = net.JoinHostPort(address.IP.String(), "0")
		if address.IP == nil {
			tcpBind = ":0"
		}
	}
	tcp, err := net.Listen("tcp", tcpBind)
	if err != nil {
		return err
	}
	defer tcp.Close()
	if ready != nil {
		ready <- [2]net.Addr{udp.LocalAddr(), tcp.Addr()}
	}
	go func() {
		<-ctx.Done()
		_ = udp.Close()
		_ = tcp.Close()
	}()
	failures := make(chan error, 2)
	go func() { failures <- s.serveUDP(ctx, udp) }()
	go func() { failures <- s.serveTCP(ctx, tcp) }()
	err = <-failures
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// udpQueries reads queries and writes their answers. IPv6 answers leave from
// the address their query was sent to: a query redirected by the firewall
// (REDIRECT picks one of the interface's addresses) is translated back only
// when its answer comes from that same address, and an interface with
// several IPv6 addresses would otherwise answer from whichever the kernel
// prefers for the client.
type udpQueries struct {
	listener *net.UDPConn
	ipv6     *ipv6.PacketConn
}

func newUDPQueries(listener *net.UDPConn) udpQueries {
	queries := udpQueries{listener: listener}
	if address, ok := listener.LocalAddr().(*net.UDPAddr); ok && address.IP.To4() == nil {
		packets := ipv6.NewPacketConn(listener)
		if packets.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true) == nil {
			queries.ipv6 = packets
		}
	}
	return queries
}

// read returns one query and a function that sends its answer.
func (q udpQueries) read(buffer []byte) (int, netip.AddrPort, func([]byte), error) {
	if q.ipv6 == nil {
		n, client, err := q.listener.ReadFromUDPAddrPort(buffer)
		return n, client, func(response []byte) { _, _ = q.listener.WriteToUDPAddrPort(response, client) }, err
	}
	n, control, source, err := q.ipv6.ReadFrom(buffer)
	if err != nil {
		return 0, netip.AddrPort{}, nil, err
	}
	address, ok := source.(*net.UDPAddr)
	if !ok {
		return 0, netip.AddrPort{}, nil, errors.New("UDP query from a non-UDP address")
	}
	client := netip.AddrPortFrom(address.AddrPort().Addr().Unmap(), address.AddrPort().Port())
	var reply *ipv6.ControlMessage
	if control != nil && control.Dst != nil && control.Dst.To4() == nil && client.Addr().Is6() {
		reply = &ipv6.ControlMessage{Src: control.Dst, IfIndex: control.IfIndex}
	}
	return n, client, func(response []byte) { _, _ = q.ipv6.WriteTo(response, reply, source) }, nil
}

func (s *Server) serveUDP(ctx context.Context, listener *net.UDPConn) error {
	semaphore := make(chan struct{}, s.MaxConcurrent)
	queries := newUDPQueries(listener)
	for {
		buffer := make([]byte, maximumDNSMessage)
		n, client, reply, err := queries.read(buffer)
		if err != nil {
			return err
		}
		query := append([]byte(nil), buffer[:n]...)
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				response, note := s.answer(ctx, "udp", query, client.Addr())
				if len(response) != 0 {
					reply(response)
					s.observe("udp", client, query, response, note)
				}
			}()
		default:
			response := servfail(query)
			if len(response) != 0 {
				reply(response)
			}
			s.logFailure("udp", query, errors.New("DNS concurrency limit reached"))
		}
	}
}

func (s *Server) serveTCP(ctx context.Context, listener net.Listener) error {
	semaphore := make(chan struct{}, s.MaxConcurrent)
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				defer connection.Close()
				s.handleTCPConnection(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (s *Server) handleTCPConnection(ctx context.Context, connection net.Conn) {
	client := netip.AddrPort{}
	if remote, err := netip.ParseAddrPort(connection.RemoteAddr().String()); err == nil {
		client = remote
	}
	reader := bufio.NewReader(connection)
	for {
		_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
		var length uint16
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return
		}
		if length < minimumDNSMessage {
			return
		}
		query := make([]byte, int(length))
		if _, err := io.ReadFull(reader, query); err != nil {
			return
		}
		response, note := s.answer(ctx, "tcp", query, client.Addr())
		if len(response) == 0 || len(response) > maximumDNSMessage {
			return
		}
		if err := binary.Write(connection, binary.BigEndian, uint16(len(response))); err != nil {
			return
		}
		if _, err := connection.Write(response); err != nil {
			return
		}
		s.observe("tcp", client, query, response, note)
	}
}

// answer returns the response for one query: NXDOMAIN for a name blocked for
// the client's device, the first valid upstream answer, or SERVFAIL.
func (s *Server) answer(ctx context.Context, network string, query []byte, client netip.Addr) ([]byte, answerNote) {
	runtime, _ := s.Provider.Runtime()
	if !runtime.AllowedClient(client) {
		// Silently ignore: answering would make this an open resolver.
		if s.Logger != nil && s.blockLog.allow("refused|"+client.String(), time.Now()) {
			s.Logger.Warn("DNS query from outside the lab ignored", "client", client.String())
		}
		return nil, answerNote{}
	}
	response, note, err := s.exchange(ctx, network, query, client)
	if err != nil {
		s.logFailure(network, query, err)
		return servfail(query), answerNote{}
	}
	return response, note
}

func (s *Server) exchange(ctx context.Context, network string, query []byte, client netip.Addr) ([]byte, answerNote, error) {
	if err := validateQuery(query); err != nil {
		return nil, answerNote{}, err
	}
	runtime, err := s.Provider.Runtime()
	if err != nil {
		return nil, answerNote{}, err
	}
	if name, nameErr := QuestionName(query); nameErr == nil {
		if deviceID, domain, blocked := runtime.Blocked(client.Unmap(), name); blocked {
			s.logBlocked(deviceID, domain, name)
			return nxdomain(query), answerNote{blocked: true, domain: domain, reason: trafficpolicy.BlockReasonDeviceDomain}, nil
		}
		// Refusing resolver names makes browsers and phones fall back from
		// DNS over HTTPS/TLS to the plain DNS ShakerProxy answers and sees.
		if refused, reason, blocked := runtime.BlockedResolverName(name); blocked {
			s.logBlocked(client.Unmap().String(), refused, name)
			return nxdomain(query), answerNote{blocked: true, domain: refused, reason: reason}, nil
		}
	}
	if len(runtime.Upstreams) == 0 {
		return nil, answerNote{}, errors.New("no DNS upstreams are configured")
	}
	response, err := s.forward(ctx, network, query, runtime.Upstreams)
	return response, answerNote{}, err
}

// observe hands an answered query to the Observer. It runs after the answer
// was written, so recording never delays a device's DNS.
func (s *Server) observe(network string, client netip.AddrPort, query, response []byte, note answerNote) {
	if s.Observer == nil {
		return
	}
	lookup, err := NewLookup(time.Now(), network, client, query, response)
	if err != nil {
		return
	}
	lookup.Blocked, lookup.BlockedDomain, lookup.BlockedReason = note.blocked, note.domain, note.reason
	s.Observer.ObserveLookup(lookup)
}

type upstreamResult struct {
	upstream string
	response []byte
	err      error
}

// forward queries upstreams in health order. A silent upstream is hedged by
// the next one after HedgeDelay and a failed one is replaced immediately, so a
// dead first upstream no longer costs the full timeout. Failing upstreams are
// marked down for 30 seconds and tried last.
func (s *Server) forward(ctx context.Context, network string, query []byte, upstreams []string) ([]byte, error) {
	start := int(s.nextUpstream.Add(1)-1) % len(upstreams)
	ordered := s.health.order(upstreams, start, time.Now())
	parallel := min(len(ordered), maxParallelUpstream)
	requestCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	results := make(chan upstreamResult, len(ordered))
	launched := 0
	launch := func() {
		upstream := ordered[launched]
		launched++
		go func() {
			response, err := exchangeDNS(requestCtx, network, upstream, query)
			if err == nil && !validResponse(query, response) {
				err = errors.New("upstream returned an invalid DNS response")
			}
			results <- upstreamResult{upstream: upstream, response: response, err: err}
		}()
	}
	launch()
	pending := 1
	hedge := time.NewTimer(s.hedgeDelay())
	defer hedge.Stop()
	var lastErr error
	for pending > 0 {
		select {
		case result := <-results:
			pending--
			if result.err == nil {
				s.health.up(result.upstream)
				return result.response, nil
			}
			s.health.down(result.upstream, time.Now())
			lastErr = fmt.Errorf("%s: %w", result.upstream, result.err)
			// A failed attempt frees a slot: every upstream gets a try,
			// with at most `parallel` in flight.
			if launched < len(ordered) {
				launch()
				pending++
			}
		case <-hedge.C:
			if launched < len(ordered) && pending < parallel {
				launch()
				pending++
				hedge.Reset(s.hedgeDelay())
			}
		case <-requestCtx.Done():
			return nil, fmt.Errorf("DNS upstreams did not answer within %s", s.Timeout)
		}
	}
	return nil, fmt.Errorf("all DNS upstreams failed: %w", lastErr)
}

func (s *Server) hedgeDelay() time.Duration {
	if s.HedgeDelay > 0 {
		return s.HedgeDelay
	}
	return min(s.Timeout/4, 500*time.Millisecond)
}

type upstreamHealth struct {
	mu        sync.Mutex
	downUntil map[string]time.Time
}

func (h *upstreamHealth) order(upstreams []string, start int, now time.Time) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	healthy := make([]string, 0, len(upstreams))
	down := []string{}
	for offset := range upstreams {
		upstream := upstreams[(start+offset)%len(upstreams)]
		if until, ok := h.downUntil[upstream]; ok && now.Before(until) {
			down = append(down, upstream)
			continue
		}
		healthy = append(healthy, upstream)
	}
	return append(healthy, down...)
}

func (h *upstreamHealth) down(upstream string, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.downUntil == nil {
		h.downUntil = map[string]time.Time{}
	}
	if len(h.downUntil) > 64 {
		h.downUntil = map[string]time.Time{}
	}
	h.downUntil[upstream] = now.Add(upstreamDownFor)
}

func (h *upstreamHealth) up(upstream string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.downUntil, upstream)
}

func exchangeDNS(ctx context.Context, network, upstream string, query []byte) ([]byte, error) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, network, upstream)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if network == "tcp" {
		if err := binary.Write(connection, binary.BigEndian, uint16(len(query))); err != nil {
			return nil, err
		}
	}
	if _, err := connection.Write(query); err != nil {
		return nil, err
	}
	if network == "tcp" {
		var length uint16
		if err := binary.Read(connection, binary.BigEndian, &length); err != nil {
			return nil, err
		}
		if length < minimumDNSMessage {
			return nil, errors.New("upstream DNS response length is invalid")
		}
		response := make([]byte, int(length))
		_, err := io.ReadFull(connection, response)
		return response, err
	}
	response := make([]byte, maximumDNSMessage)
	n, err := connection.Read(response)
	return response[:n], err
}

func (s *Server) logFailure(transport string, query []byte, err error) {
	if s.Logger == nil {
		return
	}
	name, _ := QuestionName(query)
	s.Logger.Warn("DNS query failed", "transport", transport, "qname", name, "error", err)
}

func (s *Server) logBlocked(deviceID, domain, name string) {
	if s.Logger == nil || !s.blockLog.allow(deviceID+"|"+name, time.Now()) {
		return
	}
	s.Logger.Info("DNS query blocked", "device_id", deviceID, "qname", name, "blocked_domain", domain)
}

// blockLogLimiter logs each blocked device/name pair at most once a minute so
// a retrying device cannot flood the journal.
type blockLogLimiter struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (l *blockLogLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil || len(l.seen) > maxBlockLogEntries {
		l.seen = map[string]time.Time{}
	}
	if last, ok := l.seen[key]; ok && now.Sub(last) < blockLogInterval {
		return false
	}
	l.seen[key] = now
	return true
}
