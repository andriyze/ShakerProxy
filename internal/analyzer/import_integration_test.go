package analyzer

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/pcapng/pcapngtest"
)

// pcapngProcessor accepts any well-formed PCAPNG and emits one Zeek conn.log
// record, so the offline Runner's discovery and delivery of an imported
// capture is exercised without the real analyzer image. (Real Zeek event
// extraction from a recorded capture is covered by TestLiveZeekEndToEnd.)
type pcapngProcessor struct{}

func (pcapngProcessor) Analyze(_ context.Context, file *os.File, directory string) ([]EventFile, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(file, header); err != nil {
		return nil, errors.New("import processor did not receive the capture")
	}
	if binary.BigEndian.Uint32(header) != 0x0a0d0d0a {
		return nil, errors.New("import processor received a non-PCAPNG file")
	}
	path := filepath.Join(directory, "conn.log")
	if err := os.WriteFile(path, []byte(`{"ts":1758362400.0,"uid":"Cimport"}`+"\n"), 0o600); err != nil {
		return nil, err
	}
	return []EventFile{{Path: path, ZeekPath: "conn"}}, nil
}

// An imported .pcapng becomes a finalized capture the offline analyzer
// discovers, processes and delivers like any recording.
func TestOfflineAnalyzerProcessesAnImportedCapture(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "captures")
	state := filepath.Join(base, "state")
	work := filepath.Join(base, "work")
	for _, directory := range []string{state, work} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	manager := &capture.ImportManager{Store: capture.Store{Root: root}, TempRoot: filepath.Join(base, "import-tmp")}
	frame := make([]byte, 60)
	frame[12], frame[13] = 0x08, 0x00
	data := pcapngtest.File(1, []pcapngtest.RawPacket{
		{At: time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC), Data: frame},
		{At: time.Date(2026, 9, 20, 10, 0, 1, 0, time.UTC), Data: frame},
	})
	id, err := manager.Begin("imported capture", "", "operator", "", "")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	result, err := manager.Append(id, 0, data, true)
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	sender := &recordingSender{}
	runner := testRunner(t, root, state, work, EngineZeek, pcapngProcessor{}, sender)
	scan := runner.RunOnce(context.Background())
	if len(scan.Errors) != 0 || scan.Completed != 1 || scan.Events != 1 || len(sender.events) != 1 {
		t.Fatalf("offline scan of the import = %#v (events=%d)", scan, len(sender.events))
	}

	// A second scan re-uses the checkpoint and does no work.
	again := runner.RunOnce(context.Background())
	if again.Completed != 0 || again.Events != 0 || len(sender.events) != 1 {
		t.Fatalf("the import was re-analyzed: %#v", again)
	}
	if result.SessionID != id || result.Packets != 2 {
		t.Fatalf("unexpected import result: %#v", result)
	}
}
