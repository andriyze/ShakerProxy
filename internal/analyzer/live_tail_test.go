package analyzer

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// liveSender records batches; it is safe for the live follower's goroutine.
type liveSender struct {
	mutex   sync.Mutex
	events  [][]byte
	batches int
	fail    bool
}

func (s *liveSender) Send(ctx context.Context, engine Engine, session string, event []byte) error {
	_, err := s.SendBatch(ctx, engine, session, [][]byte{event})
	return err
}

func (s *liveSender) SendBatch(_ context.Context, engine Engine, session string, events [][]byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.fail {
		return 0, errors.New("ingest unavailable")
	}
	if engine != EngineZeek || session != testSessionID || len(events) == 0 || len(events) > MaxDeliveryBatchEvents {
		return 0, errors.New("unexpected live batch")
	}
	s.batches++
	for _, event := range events {
		s.events = append(s.events, append([]byte(nil), event...))
	}
	return 0, nil
}

func (s *liveSender) setFail(fail bool) {
	s.mutex.Lock()
	s.fail = fail
	s.mutex.Unlock()
}

// byPath returns delivered events grouped by Zeek log.
func (s *liveSender) byPath(t *testing.T) map[string][]map[string]any {
	t.Helper()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	grouped := map[string][]map[string]any{}
	for _, event := range s.events {
		var fields map[string]any
		if err := json.Unmarshal(event, &fields); err != nil {
			t.Fatalf("delivered event is not JSON: %s", event)
		}
		path, _ := fields["_path"].(string)
		grouped[path] = append(grouped[path], fields)
	}
	return grouped
}

func appendFile(t *testing.T, path, data string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString(data); err != nil {
		t.Fatal(err)
	}
}

func TestZeekLogTailDeliversEachCompletedLineOnce(t *testing.T) {
	directory := t.TempDir()
	tail := newZeekLogTail(directory)
	defer tail.Close()
	sender := &liveSender{}
	conn := filepath.Join(directory, "conn.log")
	appendFile(t, conn, `{"ts":1790000000.5,"uid":"C1"}`+"\n"+`{"ts":1790000001.5,"ui`)
	appendFile(t, filepath.Join(directory, "packet_filter.log"), `{"ts":1790000000.0,"node":"zeek"}`+"\n")
	if err := tail.Poll(); err != nil {
		t.Fatal(err)
	}
	if tail.Pending() != 1 {
		t.Fatalf("a half-written line was taken: pending %d", tail.Pending())
	}
	appendFile(t, conn, `d":"C2"}`+"\nnot json\n"+`{"ts":1790000002.5,"uid":"C3","huge":"`+strings.Repeat("x", ingest.MaxPayloadBytes)+"\"}\n")
	appendFile(t, filepath.Join(directory, "ssl.log"), `{"ts":1790000003.5,"uid":"C4","server_name":"example.test"}`+"\n")
	if err := tail.Poll(); err != nil {
		t.Fatal(err)
	}
	sender.setFail(true)
	if delivered, err := tail.Deliver(context.Background(), sender, testSessionID); err == nil || delivered != 0 || tail.Pending() != 3 {
		t.Fatalf("failed delivery dropped records: delivered %d pending %d err %v", delivered, tail.Pending(), err)
	}
	sender.setFail(false)
	if delivered, err := tail.Deliver(context.Background(), sender, testSessionID); err != nil || delivered != 3 || tail.Pending() != 0 {
		t.Fatalf("retry delivered %d, pending %d: %v", delivered, tail.Pending(), err)
	}
	if err := tail.Poll(); err != nil || tail.Pending() != 0 {
		t.Fatalf("a delivered line came back: pending %d err %v", tail.Pending(), err)
	}
	grouped := sender.byPath(t)
	if len(grouped["conn"]) != 2 || grouped["conn"][0]["uid"] != "C1" || grouped["conn"][1]["uid"] != "C2" || len(grouped["ssl"]) != 1 || len(grouped["packet_filter"]) != 0 {
		t.Fatalf("delivered %#v", grouped)
	}
	if tail.Skipped != 2 {
		t.Fatalf("skipped %d malformed or oversized lines, want 2", tail.Skipped)
	}
}
