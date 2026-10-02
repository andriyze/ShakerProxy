package wifi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng/pcapngtest"
)

type collectingSink struct{ events []Event }

func (c *collectingSink) Publish(event Event) { c.events = append(c.events, event) }

func writeScope(t *testing.T, path string, scope ScopeFile) {
	t.Helper()
	data, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerFollowsTheRingAndResumesAfterRestart(t *testing.T) {
	directory := t.TempDir()
	ring := filepath.Join(directory, "ring")
	if err := os.Mkdir(ring, 0o750); err != nil {
		t.Fatal(err)
	}
	scopePath := filepath.Join(directory, "scope.json")
	statePath := filepath.Join(directory, "state.json")
	packets := scenario()
	file := pcapngtest.File(LinkTypeRadiotap, packets)
	first := filepath.Join(ring, "wifi_00001_20261002120000.pcapng")
	// The newest file is still being written.
	if err := os.WriteFile(first, file[:len(file)-20], 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ring, "notes.txt"), []byte("ignored"), 0o640); err != nil {
		t.Fatal(err)
	}
	sink := &collectingSink{}
	now := testAt.Add(time.Second)
	worker := &Worker{RingDirectory: ring, ScopePath: scopePath, Sink: sink, Now: func() time.Time { return now }}
	// No scope yet: nothing may be recorded.
	worker.Pass(context.Background())
	if len(sink.events) != 0 {
		t.Fatalf("events without a scope: %v", kinds(sink.events))
	}
	worker = &Worker{RingDirectory: ring, ScopePath: scopePath, StatePath: statePath, Sink: sink, Now: func() time.Time { return now }}
	writeScope(t, scopePath, ScopeFile{Schema: ScopeSchema, LabBSSIDs: []string{labAP}, LabSSIDs: []string{"ShakerProxy-Lab"}, LabMACs: []string{phone}, GeneratedAt: testAt})
	worker.Pass(context.Background())
	before := len(sink.events)
	if before == 0 {
		t.Fatal("no events from the partial file")
	}
	// dumpcap finishes the file and starts the next one.
	if err := os.WriteFile(first, file, 0o640); err != nil {
		t.Fatal(err)
	}
	second := pcapngtest.File(LinkTypeRadiotap, []pcapngtest.RawPacket{{At: testAt.Add(3 * time.Minute), Data: packets[3].Data}})
	if err := os.WriteFile(filepath.Join(ring, "wifi_00002_20261002120300.pcapng"), second, 0o640); err != nil {
		t.Fatal(err)
	}
	now = testAt.Add(4 * time.Minute)
	worker.Pass(context.Background())
	worker.saveState()
	if !worker.done["wifi_00001_20261002120000.pcapng"] {
		t.Fatal("the finished file was not marked done")
	}
	after := len(sink.events)
	if after <= before {
		t.Fatalf("no events after the file finished: %d", after)
	}
	// A restarted worker reads neither file again.
	restarted := &Worker{RingDirectory: ring, ScopePath: scopePath, StatePath: statePath, Sink: sink, Now: func() time.Time { return now }}
	restarted.Pass(context.Background())
	if len(sink.events) != after {
		t.Fatalf("a restart repeated %d events", len(sink.events)-after)
	}
	// The ring removed the old file: the worker forgets it.
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	restarted.Pass(context.Background())
	if restarted.done["wifi_00001_20261002120000.pcapng"] {
		t.Fatal("a removed file is still tracked")
	}
}

func TestWorkerStopsRecordingWhenTheScopeIsInvalid(t *testing.T) {
	directory := t.TempDir()
	scopePath := filepath.Join(directory, "scope.json")
	writeScope(t, scopePath, ScopeFile{Schema: ScopeSchema, LabMACs: []string{phone}, GeneratedAt: testAt})
	worker := &Worker{RingDirectory: directory, ScopePath: scopePath, Sink: &collectingSink{}, Now: func() time.Time { return testAt }}
	worker.Pass(context.Background())
	if !worker.observer.scope.LabMAC(mustMAC(phone)) {
		t.Fatal("scope not loaded")
	}
	if err := os.WriteFile(scopePath, []byte(`{"schema":1,"lab_macs":["broken"]}`), 0o640); err != nil {
		t.Fatal(err)
	}
	later := testAt.Add(time.Minute)
	worker.Now = func() time.Time { return later }
	// The file's modification time changed (or the reload interval passed).
	_ = os.Chtimes(scopePath, later, later)
	worker.Pass(context.Background())
	if worker.observer.scope != nil {
		t.Fatal("an invalid scope left the previous one in force")
	}
}

func mustMAC(value string) MAC {
	mac, ok := ParseMAC(value)
	if !ok {
		panic(value)
	}
	return mac
}
