//go:build linux

package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

// TestLiveZeekEndToEnd records synthetic lab traffic the way dumpcap does
// (10-second ring-buffer segments written a packet at a time) and analyzes it
// twice with the real Zeek and site scripts: once with only the per-segment
// offline pass, once with live analysis. It reports how long each record took
// from its packets to ingest and checks that live analysis delivers the same
// connection totals without the offline pass delivering anything twice.
//
// It needs the Zeek analyzer image and parser isolation privileges:
//
//	docker build -f apps/analyzer-worker/Dockerfile.zeek -t shakerproxy-zeek:live-test .
//	go test -c -o analyzer.test ./internal/analyzer
//	docker run --rm --user 0:0 --cap-drop ALL --cap-add SETUID --cap-add SETGID \
//	  --security-opt no-new-privileges -e SHAKERPROXY_LIVE_ZEEK_INTEGRATION=1 \
//	  -v "$PWD/analyzer.test:/analyzer.test:ro" --entrypoint /analyzer.test \
//	  shakerproxy-zeek:live-test -test.run TestLiveZeekEndToEnd -test.v
//
// SHAKERPROXY_LIVE_REPLAY_PCAP names a classic little-endian pcap to replay
// instead of the synthetic traffic, restamped to the time it is replayed.
func TestLiveZeekEndToEnd(t *testing.T) {
	if os.Getenv("SHAKERPROXY_LIVE_ZEEK_INTEGRATION") != "1" {
		t.Skip("set SHAKERPROXY_LIVE_ZEEK_INTEGRATION=1 to run inside the Zeek analyzer image")
	}
	traffic := syntheticLabTraffic()
	if path := os.Getenv("SHAKERPROXY_LIVE_REPLAY_PCAP"); path != "" {
		traffic = replayTraffic(t, path)
	}
	offline := recordLab(t, false, traffic)
	live := recordLab(t, true, traffic)
	t.Logf("%-14s %28s %28s", "log", "offline p50 / max (n)", "live p50 / max (n)")
	paths := map[string]bool{}
	for path := range offline.latencies {
		paths[path] = true
	}
	for path := range live.latencies {
		paths[path] = true
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	for _, path := range ordered {
		t.Logf("%-14s %28s %28s", path, summarizeLatency(offline.latencies[path]), summarizeLatency(live.latencies[path]))
	}
	if live.offlineEvents != 0 {
		t.Fatalf("the offline pass delivered %d events for segments live analysis covered", live.offlineEvents)
	}
	if offline.offlineEvents == 0 || live.liveEvents == 0 {
		t.Fatalf("offline delivered %d, live %d", offline.offlineEvents, live.liveEvents)
	}
	if live.duplicates != 0 {
		t.Fatalf("live analysis delivered %d identical events twice", live.duplicates)
	}
	if os.Getenv("SHAKERPROXY_LIVE_REPLAY_PCAP") == "" {
		t.Logf("long connection bytes across its records: offline %v, live %v (sent 2500/25000)", offline.longFlow, live.longFlow)
		if live.longFlow != [2]float64{2500, 25000} {
			t.Fatalf("live long connection bytes %v, want 2500/25000 across its records", live.longFlow)
		}
		for _, path := range []string{"dns", "http", "ssl", "conn closed", "conn window"} {
			if len(live.latencies[path]) == 0 {
				t.Fatalf("live analysis delivered no %s records", path)
			}
		}
	}
}

type trafficPacket struct {
	delay time.Duration
	frame []byte
}

type labRun struct {
	latencies     map[string][]time.Duration
	liveEvents    uint64
	offlineEvents int
	duplicates    int
	longFlow      [2]float64
}

func summarizeLatency(values []time.Duration) string {
	if len(values) == 0 {
		return "-"
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return fmt.Sprintf("%.2fs / %.2fs (%d)", sorted[len(sorted)/2].Seconds(), sorted[len(sorted)-1].Seconds(), len(sorted))
}

type ingestRecord struct {
	at     time.Time
	fields map[string]any
	raw    string
}

func recordLab(t *testing.T, live bool, traffic []trafficPacket) labRun {
	t.Helper()
	base, err := os.MkdirTemp("", "live-zeek-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	root, state, work := filepath.Join(base, "pcap"), filepath.Join(base, "state"), filepath.Join(base, "work")
	session := filepath.Join(root, testSessionID)
	artifacts, runtime := filepath.Join(session, "artifacts"), filepath.Join(session, "runtime")
	for _, directory := range []string{artifacts, runtime} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeJSONFixture(t, filepath.Join(session, "session.json"), map[string]any{"id": testSessionID, "request": map[string]any{"automatic": true}})
	writeJSONFixture(t, filepath.Join(runtime, "worker-status.json"), map[string]any{"schema": capture.SchemaVersion, "session_id": testSessionID, "state": capture.StateRunning})

	var mutex sync.Mutex
	var received []ingestRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		at := time.Now()
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		results := make([]map[string]any, 0, len(lines))
		mutex.Lock()
		for index, line := range lines {
			var fields map[string]any
			if json.Unmarshal([]byte(line), &fields) == nil {
				received = append(received, ingestRecord{at: at, fields: fields, raw: line})
			}
			results = append(results, map[string]any{"accepted": true, "record_id": fmt.Sprintf("r%d", index)})
		}
		mutex.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"schema": 1, "results": results})
	}))
	defer server.Close()

	runner, err := NewRunner(Config{Engine: EngineZeek, CaptureRoot: root, StateRoot: state, WorkRoot: work, IngestURL: server.URL, Token: []byte(strings.Repeat("t", 32)), SourceVersion: "8.2.1", PollInterval: DefaultPollInterval})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	var analyzer *LiveAnalyzer
	if live {
		coverage, err := NewLiveCoverage(runner.State, root, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		runner.Live = coverage
		analyzer = NewLiveAnalyzer(runner, coverage, nil)
		workers.Add(1)
		go func() {
			defer workers.Done()
			analyzer.Run(ctx)
		}()
	}
	offlineEvents := 0
	workers.Add(1)
	go func() {
		defer workers.Done()
		for ctx.Err() == nil {
			result := runner.RunOnce(ctx)
			mutex.Lock()
			offlineEvents += result.Events
			mutex.Unlock()
			for _, err := range result.Errors {
				if ctx.Err() == nil {
					t.Logf("offline scan: %v", err)
				}
			}
			sleepContext(ctx, runner.Config.PollInterval)
		}
	}()

	recorder := &segmentRecorder{t: t, artifacts: artifacts, runtime: runtime}
	recorder.rotate()
	rotateAt := time.Now().Add(10 * time.Second)
	for _, packet := range append(traffic, trafficPacket{delay: 15 * time.Second}) {
		for deadline := time.Now().Add(packet.delay); time.Now().Before(deadline); {
			if time.Now().After(rotateAt) {
				recorder.rotate()
				rotateAt = rotateAt.Add(10 * time.Second)
			}
			time.Sleep(min(time.Until(deadline), 50*time.Millisecond))
		}
		if packet.frame != nil {
			recorder.write(packet.frame)
		}
	}
	recorder.stop()
	waitDeadline := time.Now().Add(90 * time.Second)
	for {
		if _, exists, _ := runner.State.ReadCheckpoint(EngineZeek, testSessionID); exists && (analyzer == nil || analyzer.Status().State == LiveStateIdle) {
			break
		}
		if time.Now().After(waitDeadline) {
			t.Fatal("analysis did not finish")
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(time.Second)
	cancel()
	workers.Wait()

	run := labRun{latencies: map[string][]time.Duration{}}
	if analyzer != nil {
		run.liveEvents = analyzer.Status().EventsDelivered
		if status := analyzer.Status(); status.SegmentsHandedOff != 0 || status.Restarts != 0 {
			t.Fatalf("live analysis handed off segments: %#v", status)
		}
	}
	mutex.Lock()
	defer mutex.Unlock()
	run.offlineEvents = offlineEvents
	seen := map[string]bool{}
	for _, record := range received {
		if seen[record.raw] {
			run.duplicates++
		}
		seen[record.raw] = true
		path, _ := record.fields["_path"].(string)
		ts, _ := record.fields["ts"].(float64)
		if ts == 0 {
			continue
		}
		at := ts
		if path == "conn" {
			// A connection record is measured from its last packet: a
			// closed connection's, or the last one of a window reported
			// while the connection was still open.
			duration, _ := record.fields["duration"].(float64)
			at += duration
			if state, _ := record.fields["conn_state"].(string); state == "SF" {
				path = "conn closed"
			} else {
				path = "conn window"
			}
			if port, _ := record.fields["id.resp_p"].(float64); port == 8443 {
				orig, _ := record.fields["orig_bytes"].(float64)
				resp, _ := record.fields["resp_bytes"].(float64)
				run.longFlow[0] += orig
				run.longFlow[1] += resp
			}
		}
		whole, fraction := math.Modf(at)
		latency := record.at.Sub(time.Unix(int64(whole), int64(fraction*1e9)))
		run.latencies[path] = append(run.latencies[path], latency)
		if live && latency > 5*time.Second {
			t.Logf("slow live record (%.1fs): %s", latency.Seconds(), record.raw)
		}
	}
	return run
}

// segmentRecorder writes ring-buffer segments like dumpcap and publishes each
// closed one like the capture worker, which polls once a second.
type segmentRecorder struct {
	t         *testing.T
	artifacts string
	runtime   string
	number    int
	file      *os.File
	writer    *bufio.Writer
	feed      capture.ActiveSegmentFeed
	files     []capture.CaptureFile
}

func (r *segmentRecorder) name() string {
	return fmt.Sprintf("capture_%05d_20261002100000.pcapng", r.number)
}

func (r *segmentRecorder) rotate() {
	r.t.Helper()
	r.close()
	r.number++
	file, err := os.OpenFile(filepath.Join(r.artifacts, r.name()), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		r.t.Fatal(err)
	}
	r.file, r.writer = file, bufio.NewWriter(file)
	_, _ = r.writer.Write(pcapngSection(binary.LittleEndian, 1, 0, nil))
	_ = r.writer.Flush()
}

func (r *segmentRecorder) write(frame []byte) {
	header := len(pcapngSection(binary.LittleEndian, 1, 0, nil))
	_, _ = r.writer.Write(pcapngSection(binary.LittleEndian, 1, 0, []livePacket{{time.Now(), frame}})[header:])
	_ = r.writer.Flush()
}

// close finishes the current segment and publishes it a second later.
func (r *segmentRecorder) close() {
	r.t.Helper()
	if r.file == nil {
		return
	}
	_ = r.writer.Flush()
	r.file.Close()
	path := filepath.Join(r.artifacts, r.name())
	contents, err := os.ReadFile(path)
	if err != nil {
		r.t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		r.t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	r.files = append(r.files, capture.CaptureFile{Name: r.name(), SizeBytes: info.Size(), SHA256: hex.EncodeToString(sum[:]), Modified: info.ModTime().UTC()})
	r.feed = capture.ActiveSegmentFeed{Schema: capture.SchemaVersion, SessionID: testSessionID, Revision: r.feed.Revision + 1, Segments: append(r.feed.Segments,
		capture.ClosedCaptureSegment{Sequence: r.feed.Revision + 1, Name: r.name(), SizeBytes: info.Size(), Modified: info.ModTime().UTC(), ClosedAt: time.Now().UTC()})}
	feed := r.feed
	time.AfterFunc(time.Second, func() {
		feed.PublishedAt = time.Now().UTC()
		encoded, _ := json.Marshal(feed)
		temporary := filepath.Join(r.runtime, ".feed")
		if os.WriteFile(temporary, append(encoded, '\n'), 0o640) == nil {
			_ = os.Rename(temporary, filepath.Join(r.runtime, "active-segments.json"))
		}
	})
	r.file = nil
}

func (r *segmentRecorder) stop() {
	r.t.Helper()
	r.close()
	time.Sleep(1500 * time.Millisecond)
	writeJSONFixture(r.t, filepath.Join(r.runtime, "worker-status.json"), map[string]any{"schema": capture.SchemaVersion, "session_id": testSessionID, "state": capture.StateCompleted})
	var total int64
	for _, file := range r.files {
		total += file.SizeBytes
	}
	writeJSONFixture(r.t, filepath.Join(r.runtime, "manifest.json"), capture.Manifest{Schema: capture.SchemaVersion, SessionID: testSessionID, CreatedAt: time.Now().UTC(), SessionSHA256: strings.Repeat("a", 64), Files: r.files, TotalSizeBytes: total})
}

var (
	labClient = [4]byte{10, 77, 0, 20}
	labServer = [4]byte{192, 0, 2, 10}
	labFlow   = [4]byte{192, 0, 2, 11}
	labTLS    = [4]byte{192, 0, 2, 12}
)

func labFrame(src, dst [4]byte, protocol byte, payload []byte) []byte {
	frame := make([]byte, 14, 34+len(payload))
	copy(frame[0:6], []byte{2, 0, 0, 0, 0, dst[3]})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, src[3]})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(payload)))
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	return append(append(frame, ip...), payload...)
}

func udpSegment(sport, dport uint16, data []byte) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header[0:2], sport)
	binary.BigEndian.PutUint16(header[2:4], dport)
	binary.BigEndian.PutUint16(header[4:6], uint16(8+len(data)))
	return append(header, data...)
}

func tcpSegment(sport, dport uint16, seq, ack uint32, flags byte, data []byte) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], sport)
	binary.BigEndian.PutUint16(header[2:4], dport)
	binary.BigEndian.PutUint32(header[4:8], seq)
	binary.BigEndian.PutUint32(header[8:12], ack)
	header[12], header[13] = 5<<4, flags
	binary.BigEndian.PutUint16(header[14:16], 65535)
	return append(header, data...)
}

// tcpConversation builds a TCP connection: handshake, the given exchanges,
// and a FIN close.
type tcpConversation struct {
	client, server [4]byte
	sport, dport   uint16
	cseq, sseq     uint32
}

func (c *tcpConversation) packet(fromClient bool, flags byte, data []byte) []byte {
	if fromClient {
		frame := labFrame(c.client, c.server, 6, tcpSegment(c.sport, c.dport, c.cseq, c.sseq, flags, data))
		c.cseq += uint32(len(data))
		if flags&0x03 != 0 {
			c.cseq++
		}
		return frame
	}
	frame := labFrame(c.server, c.client, 6, tcpSegment(c.dport, c.sport, c.sseq, c.cseq, flags, data))
	c.sseq += uint32(len(data))
	if flags&0x03 != 0 {
		c.sseq++
	}
	return frame
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpPSH = 0x08
	tcpACK = 0x10
)

func (c *tcpConversation) open() []trafficPacket {
	return []trafficPacket{
		{delay: 0, frame: c.packet(true, tcpSYN, nil)},
		{delay: 5 * time.Millisecond, frame: c.packet(false, tcpSYN|tcpACK, nil)},
		{delay: 5 * time.Millisecond, frame: c.packet(true, tcpACK, nil)},
	}
}

func (c *tcpConversation) close() []trafficPacket {
	return []trafficPacket{
		{delay: 5 * time.Millisecond, frame: c.packet(true, tcpFIN|tcpACK, nil)},
		{delay: 5 * time.Millisecond, frame: c.packet(false, tcpFIN|tcpACK, nil)},
		{delay: 5 * time.Millisecond, frame: c.packet(true, tcpACK, nil)},
	}
}

func dnsMessage(response bool) []byte {
	message := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	if response {
		message[2], message[3], message[7] = 0x81, 0x80, 1
	}
	for _, label := range []string{"live", "example", "test"} {
		message = append(append(message, byte(len(label))), label...)
	}
	message = append(message, 0, 0, 1, 0, 1)
	if response {
		message = append(message, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 10)
	}
	return message
}

func tlsRecord(contentType byte, body []byte) []byte {
	record := []byte{contentType, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(record[3:5], uint16(len(body)))
	return append(record, body...)
}

func tlsHandshake(messageType byte, body []byte) []byte {
	return append([]byte{messageType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func tlsClientHello(serverName string) []byte {
	name := append([]byte{0, byte(len(serverName) >> 8), byte(len(serverName))}, serverName...)
	list := append([]byte{byte(len(name) >> 8), byte(len(name))}, name...)
	extension := append([]byte{0, 0, byte(len(list) >> 8), byte(len(list))}, list...)
	body := append([]byte{3, 3}, bytes.Repeat([]byte{7}, 32)...)
	body = append(body, 0, 0, 2, 0xc0, 0x2f, 1, 0, byte(len(extension)>>8), byte(len(extension)))
	return tlsRecord(22, tlsHandshake(1, append(body, extension...)))
}

func tlsServerHello() []byte {
	body := append([]byte{3, 3}, bytes.Repeat([]byte{9}, 32)...)
	body = append(body, 0, 0xc0, 0x2f, 0, 0, 0)
	return append(tlsRecord(22, tlsHandshake(2, body)), tlsRecord(22, tlsHandshake(14, nil))...)
}

// syntheticLabTraffic is a 25-second connection carrying 100 bytes up and
// 1000 down every second, plus four rounds of a DNS lookup, an HTTP request,
// and a TLS connection naming its server, at different points of their
// 10-second segments.
func syntheticLabTraffic() []trafficPacket {
	type timedFrame struct {
		offset time.Duration
		frame  []byte
	}
	var timeline []timedFrame
	place := func(start time.Duration, packets []trafficPacket) {
		offset := start
		for _, packet := range packets {
			offset += packet.delay
			timeline = append(timeline, timedFrame{offset: offset, frame: packet.frame})
		}
	}
	long := &tcpConversation{client: labClient, server: labFlow, sport: 40002, dport: 8443, cseq: 5000, sseq: 3000}
	flow := long.open()
	for range 25 {
		flow = append(flow,
			trafficPacket{delay: time.Second, frame: long.packet(true, tcpPSH|tcpACK, bytes.Repeat([]byte{'c'}, 100))},
			trafficPacket{delay: 10 * time.Millisecond, frame: long.packet(false, tcpPSH|tcpACK, bytes.Repeat([]byte{'s'}, 1000))},
			trafficPacket{delay: 5 * time.Millisecond, frame: long.packet(true, tcpACK, nil)})
	}
	place(500*time.Millisecond, append(flow, long.close()...))
	for round, start := range []time.Duration{3200 * time.Millisecond, 11700 * time.Millisecond, 16400 * time.Millisecond, 22900 * time.Millisecond} {
		port := uint16(41000 + 10*round)
		exchange := []trafficPacket{
			{delay: 0, frame: labFrame(labClient, labServer, 17, udpSegment(port, 53, dnsMessage(false)))},
			{delay: 20 * time.Millisecond, frame: labFrame(labServer, labClient, 17, udpSegment(53, port, dnsMessage(true)))},
		}
		web := &tcpConversation{client: labClient, server: labServer, sport: port + 1, dport: 80, cseq: 1000, sseq: 9000}
		exchange = append(exchange, web.open()...)
		exchange = append(exchange,
			trafficPacket{delay: 5 * time.Millisecond, frame: web.packet(true, tcpPSH|tcpACK, []byte("GET / HTTP/1.1\r\nHost: live.example.test\r\n\r\n"))},
			trafficPacket{delay: 20 * time.Millisecond, frame: web.packet(false, tcpPSH|tcpACK, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))})
		exchange = append(exchange, web.close()...)
		secure := &tcpConversation{client: labClient, server: labTLS, sport: port + 2, dport: 443, cseq: 2000, sseq: 7000}
		exchange = append(exchange, secure.open()...)
		exchange = append(exchange,
			trafficPacket{delay: 5 * time.Millisecond, frame: secure.packet(true, tcpPSH|tcpACK, tlsClientHello("tls.example.test"))},
			trafficPacket{delay: 20 * time.Millisecond, frame: secure.packet(false, tcpPSH|tcpACK, tlsServerHello())},
			trafficPacket{delay: 5 * time.Millisecond, frame: secure.packet(true, tcpPSH|tcpACK, append(tlsRecord(20, []byte{1}), tlsRecord(23, bytes.Repeat([]byte{1}, 40))...))},
			trafficPacket{delay: 5 * time.Millisecond, frame: secure.packet(false, tcpPSH|tcpACK, append(tlsRecord(20, []byte{1}), tlsRecord(23, bytes.Repeat([]byte{2}, 40))...))})
		exchange = append(exchange, secure.close()...)
		place(start, exchange)
	}
	sort.SliceStable(timeline, func(i, j int) bool { return timeline[i].offset < timeline[j].offset })
	traffic := make([]trafficPacket, 0, len(timeline))
	var previous time.Duration
	for _, timed := range timeline {
		traffic = append(traffic, trafficPacket{delay: timed.offset - previous, frame: timed.frame})
		previous = timed.offset
	}
	return traffic
}

// replayTraffic reads a classic little-endian microsecond pcap and keeps its
// pacing, with gaps capped at 300 ms.
func replayTraffic(t *testing.T, path string) []trafficPacket {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) < 24 || binary.LittleEndian.Uint32(contents[:4]) != pcapMagicMicroseconds || binary.LittleEndian.Uint32(contents[20:24]) != 1 {
		t.Fatalf("replay capture must be a little-endian microsecond Ethernet pcap: %v", err)
	}
	var traffic []trafficPacket
	var previous time.Time
	for offset := 24; offset+16 <= len(contents); {
		at := time.Unix(int64(binary.LittleEndian.Uint32(contents[offset:])), int64(binary.LittleEndian.Uint32(contents[offset+4:]))*1000)
		length := int(binary.LittleEndian.Uint32(contents[offset+8:]))
		if offset+16+length > len(contents) {
			break
		}
		delay := 500 * time.Millisecond
		if !previous.IsZero() {
			delay = min(max(at.Sub(previous), 0), 300*time.Millisecond)
		}
		previous = at
		traffic = append(traffic, trafficPacket{delay: delay, frame: append([]byte(nil), contents[offset+16:offset+16+length]...)})
		offset += 16 + length
	}
	return traffic
}
