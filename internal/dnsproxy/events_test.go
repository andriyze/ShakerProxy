package dnsproxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// answerFor builds a response to queryFor(name): a CNAME to cdn.example.net,
// an A and an AAAA record for the target, and an MX record.
func answerFor(name string) []byte {
	response := queryFor(name)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 4)
	target := len(response) + 12
	record := func(owner []byte, recordType uint16, ttl uint32, data []byte) {
		response = append(response, owner...)
		response = binary.BigEndian.AppendUint16(response, recordType)
		response = binary.BigEndian.AppendUint16(response, 1)
		response = binary.BigEndian.AppendUint32(response, ttl)
		response = binary.BigEndian.AppendUint16(response, uint16(len(data)))
		response = append(response, data...)
	}
	question := []byte{0xc0, 0x0c}
	record(question, 5, 300, []byte{3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0})
	alias := []byte{0xc0 | byte(target>>8), byte(target)}
	record(alias, 1, 60, []byte{93, 184, 216, 34})
	record(alias, 28, 60, netip.MustParseAddr("2606:2800:220:1::248").AsSlice())
	record(question, 15, 60, []byte{0, 10, 0xc0, 0x0c})
	return response
}

func TestNewLookupReadsTheQuestionAndAnswers(t *testing.T) {
	client := netip.MustParseAddrPort("[::ffff:192.168.10.201]:40000")
	lookup, err := NewLookup(time.Unix(100, 0), "udp", client, queryFor("api.example.com"), answerFor("api.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if lookup.Name != "api.example.com" || lookup.Type != "A" || lookup.Rcode != "NOERROR" || lookup.AnswerCount != 4 || lookup.Client.Addr().String() != "192.168.10.201" {
		t.Fatalf("unexpected lookup: %+v", lookup)
	}
	want := []Answer{
		{Name: "api.example.com", Type: "CNAME", TTL: 300, Data: "cdn.example.net"},
		{Name: "cdn.example.net", Type: "A", TTL: 60, Data: "93.184.216.34"},
		{Name: "cdn.example.net", Type: "AAAA", TTL: 60, Data: "2606:2800:220:1::248"},
		{Name: "api.example.com", Type: "MX", TTL: 60},
	}
	if len(lookup.Answers) != len(want) {
		t.Fatalf("answers = %+v", lookup.Answers)
	}
	for index := range want {
		if lookup.Answers[index] != want[index] {
			t.Fatalf("answer %d = %+v, want %+v", index, lookup.Answers[index], want[index])
		}
	}
	failed, err := NewLookup(time.Unix(100, 0), "tcp", client, queryFor("gone.example"), nxdomain(queryFor("gone.example")))
	if err != nil || failed.Rcode != "NXDOMAIN" || failed.AnswerCount != 0 || len(failed.Answers) != 0 {
		t.Fatalf("NXDOMAIN lookup = %+v err=%v", failed, err)
	}
	if _, err := NewLookup(time.Unix(100, 0), "udp", client, []byte{1, 2, 3}, nil); err == nil {
		t.Fatal("a query without a question was recorded")
	}
}

func TestParseAnswersStopsAtATruncatedRecord(t *testing.T) {
	response := answerFor("api.example.com")
	count, answers := parseAnswers(response[:len(response)-20])
	if count != 4 || len(answers) != 2 || answers[1].Data != "93.184.216.34" {
		t.Fatalf("truncated response: count=%d answers=%+v", count, answers)
	}
}

func TestLookupEventIsAnIngestEnvelope(t *testing.T) {
	lookup, err := NewLookup(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), "udp", netip.MustParseAddrPort("192.168.10.201:40000"), queryFor("api.example.com"), answerFor("api.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := LookupEvent("evt_00000000000000000001_00000001_abcdefabcdef", lookup)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Schema     int       `json:"schema"`
		EventID    string    `json:"event_id"`
		Source     string    `json:"source"`
		Kind       string    `json:"kind"`
		OccurredAt time.Time `json:"occurred_at"`
		Confidence int       `json:"confidence"`
		Payload    struct {
			SourceIP        string `json:"source_ip"`
			SourcePort      int    `json:"source_port"`
			DestinationPort int    `json:"destination_port"`
			Protocol        string `json:"protocol"`
			Service         string `json:"service"`
			Query           string `json:"query"`
			QueryType       string `json:"query_type"`
			ResponseCode    string `json:"response_code"`
			AnswerCount     int    `json:"answer_count"`
			Answers         []struct {
				Type string `json:"type"`
				TTL  uint32 `json:"ttl"`
				Data string `json:"data"`
			} `json:"answers"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	payload := envelope.Payload
	if envelope.Schema != 1 || envelope.Source != "HOST" || envelope.Kind != LookupEventKind || envelope.Confidence != 100 || !envelope.OccurredAt.Equal(lookup.At) {
		t.Fatalf("envelope = %s", encoded)
	}
	if payload.SourceIP != "192.168.10.201" || payload.SourcePort != 40000 || payload.DestinationPort != 53 || payload.Protocol != "udp" || payload.Service != "dns" || payload.Query != "api.example.com" || payload.QueryType != "A" || payload.ResponseCode != "NOERROR" || payload.AnswerCount != 4 || len(payload.Answers) != 4 || payload.Answers[1].Data != "93.184.216.34" || payload.Answers[1].TTL != 60 {
		t.Fatalf("payload = %s", encoded)
	}
}

type collector struct {
	mu      sync.Mutex
	lookups []Lookup
}

func (c *collector) ObserveLookup(lookup Lookup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lookups = append(c.lookups, lookup)
}

func (c *collector) wait(t *testing.T, count int) []Lookup {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		if len(c.lookups) >= count {
			lookups := append([]Lookup(nil), c.lookups...)
			c.mu.Unlock()
			return lookups
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d lookups", count)
	return nil
}

func TestServerReportsForwardedAndBlockedLookups(t *testing.T) {
	upstream := startUpstream(t, true)
	runtime, err := ParseRuntime([]byte(`{"schema_version":1,"encrypted_dns":{"redirect_plain_dns":true,"blocked_domains":{"` + testDeviceID + `":["blocked.example"]}},"device_by_ip":{"127.0.0.1":"` + testDeviceID + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	runtime.Upstreams = []string{upstream}
	observed := &collector{}
	address := startServer(t, &Server{Provider: staticProvider{runtime}, Timeout: 2 * time.Second, Observer: observed})
	ask(t, address, "allowed.example")
	ask(t, address, "www.blocked.example")
	lookups := observed.wait(t, 2)
	if lookups[0].Name != "allowed.example" || lookups[0].Blocked || lookups[0].Rcode != "NOERROR" || lookups[0].Transport != "udp" || lookups[0].Client.Addr().String() != "127.0.0.1" || lookups[0].Client.Port() == 0 {
		t.Fatalf("forwarded lookup = %+v", lookups[0])
	}
	if lookups[1].Name != "www.blocked.example" || !lookups[1].Blocked || lookups[1].BlockedDomain != "blocked.example" || lookups[1].Rcode != "NXDOMAIN" {
		t.Fatalf("blocked lookup = %+v", lookups[1])
	}
}

// blockingObserver never returns; the forwarder must answer regardless.
type blockingObserver struct{ release chan struct{} }

func (b blockingObserver) ObserveLookup(Lookup) { <-b.release }

func TestServerAnswersBeforeRecording(t *testing.T) {
	upstream := startUpstream(t, true)
	observer := blockingObserver{release: make(chan struct{})}
	t.Cleanup(func() { close(observer.release) })
	address := startServer(t, &Server{Provider: staticProvider{&Runtime{Upstreams: []string{upstream}}}, Timeout: 2 * time.Second, Observer: observer})
	if response := ask(t, address, "example.com"); rcode(response) != 0 {
		t.Fatalf("rcode %d", rcode(response))
	}
}

func TestSpoolRecorderNeverBlocksAndCountsDrops(t *testing.T) {
	recorder, err := NewSpoolRecorder(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing drains the queue: once it is full, lookups are dropped.
	done := make(chan struct{})
	go func() {
		for index := 0; index < defaultEventQueue+10; index++ {
			recorder.ObserveLookup(Lookup{Name: "example.com"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ObserveLookup blocked on a full queue")
	}
	if dropped := recorder.dropped.Load(); dropped != 10 {
		t.Fatalf("dropped = %d, want 10", dropped)
	}
}

func TestSpoolRecorderWritesReadableEventFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, ".tmp-crashed"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	recorder, err := NewSpoolRecorder(directory, nil)
	if err != nil {
		t.Fatal(err)
	}
	recorder.MaxPending = 2
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { recorder.Run(ctx); close(stopped) }()
	for index, name := range []string{"one.example", "two.example", "three.example"} {
		lookup, err := NewLookup(time.Unix(int64(100+index), 0), "udp", netip.MustParseAddrPort("192.168.10.201:5353"), queryFor(name), answerFor(name))
		if err != nil {
			t.Fatal(err)
		}
		recorder.ObserveLookup(lookup)
	}
	deadline := time.Now().Add(3 * time.Second)
	for recorder.dropped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-stopped
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != 2 || recorder.dropped.Load() != 1 {
		t.Fatalf("spool should hold two events and drop the third: %v dropped=%d", names, recorder.dropped.Load())
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "evt_") || !strings.HasSuffix(name, ".json") {
			t.Fatalf("unexpected spool file %q", name)
		}
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode = %v err=%v", name, info.Mode(), err)
		}
		data, _ := os.ReadFile(filepath.Join(directory, name))
		var envelope struct {
			EventID string `json:"event_id"`
		}
		if json.Unmarshal(data, &envelope) != nil || envelope.EventID+".json" != name {
			t.Fatalf("%s does not name its event: %s", name, data)
		}
	}
	if names[0] > names[1] || !strings.Contains(string(mustRead(t, filepath.Join(directory, names[0]))), "one.example") {
		t.Fatalf("spool order is not chronological: %v", names)
	}
}

func TestSpoolRecorderRejectsAMissingSpool(t *testing.T) {
	if _, err := NewSpoolRecorder(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("a missing spool was accepted")
	}
	if _, err := NewSpoolRecorder("relative/spool", nil); err == nil {
		t.Fatal("a relative spool was accepted")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
