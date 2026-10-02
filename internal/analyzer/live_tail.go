package analyzer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const (
	// maxLiveReadPerPoll bounds how much log output one poll reads, and
	// maxLivePendingBytes how much read output may wait for delivery.
	maxLiveReadPerPoll  = 4 << 20
	maxLivePendingBytes = 8 << 20
	liveSendTimeout     = 10 * time.Second
)

// zeekLogTail follows the JSON logs a running Zeek writes into its work
// directory and turns each completed line into an ingest event. Zeek writes
// whole records, but a reader can still see one half written, so only lines
// ending in a newline are taken.
type zeekLogTail struct {
	directory string
	logs      map[string]*tailedLog
	pending   [][]byte
	pendingSz int
	// ConsumedBytes counts log bytes read so far; it bounds a generation's
	// output.
	ConsumedBytes int64
	Skipped       uint64
}

type tailedLog struct {
	file       *os.File
	path       string
	offset     int64
	partial    []byte
	discarding bool
}

func newZeekLogTail(directory string) *zeekLogTail {
	return &zeekLogTail{directory: directory, logs: map[string]*tailedLog{}}
}

// Poll reads newly completed lines from every log.
func (t *zeekLogTail) Poll() error {
	entries, err := os.ReadDir(t.directory)
	if err != nil {
		return err
	}
	if len(entries) > MaxOutputFiles+8 {
		return errors.New("live analyzer output file count exceeds its safety limit")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		path, ok := strings.CutSuffix(name, ".log")
		if entry.IsDir() || !ok || !validLogName(path) || zeekIgnoredLogs[path] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	budget := maxLiveReadPerPoll
	for _, name := range names {
		if t.pendingSz >= maxLivePendingBytes || budget <= 0 {
			return nil
		}
		log := t.logs[name]
		if log == nil {
			if len(t.logs) >= MaxOutputFiles {
				return errors.New("live analyzer output file count exceeds its safety limit")
			}
			file, err := openRegularNoFollow(filepath.Join(t.directory, name))
			if err != nil {
				return err
			}
			log = &tailedLog{file: file, path: strings.TrimSuffix(name, ".log")}
			t.logs[name] = log
		}
		read, err := t.read(log, budget)
		if err != nil {
			return err
		}
		budget -= read
	}
	return nil
}

func (t *zeekLogTail) read(log *tailedLog, budget int) (int, error) {
	buffer := make([]byte, min(budget, 1<<20))
	total := 0
	for total < budget {
		count, err := log.file.ReadAt(buffer[:min(len(buffer), budget-total)], log.offset)
		if count > 0 {
			log.offset += int64(count)
			total += count
			t.ConsumedBytes += int64(count)
			t.lines(log, buffer[:count])
		}
		if errors.Is(err, io.EOF) || count == 0 {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (t *zeekLogTail) lines(log *tailedLog, data []byte) {
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			if !log.discarding {
				log.partial = append(log.partial, data...)
				if len(log.partial) > ingest.MaxPayloadBytes {
					log.partial, log.discarding = nil, true
				}
			}
			return
		}
		line := data[:end]
		data = data[end+1:]
		if log.discarding {
			log.discarding = false
			t.Skipped++
			continue
		}
		if len(log.partial) > 0 {
			line = append(log.partial, line...)
			log.partial = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		event, err := addZeekPath(line, log.path)
		if err != nil {
			t.Skipped++
			continue
		}
		t.pending = append(t.pending, event)
		t.pendingSz += len(event) + 1
	}
}

// Pending reports events read but not yet delivered.
func (t *zeekLogTail) Pending() int { return len(t.pending) }

// Deliver sends pending events in ingest batches. Events stay pending when a
// batch fails, so a later call retries them.
func (t *zeekLogTail) Deliver(ctx context.Context, sender Sender, sessionID string) (int, error) {
	delivered := 0
	batchSender, batching := sender.(BatchSender)
	for len(t.pending) > 0 {
		count, size := 0, 0
		for count < len(t.pending) && count < MaxDeliveryBatchEvents && size+len(t.pending[count])+1 <= MaxDeliveryBatchBytes {
			size += len(t.pending[count]) + 1
			count++
		}
		sendContext, cancel := context.WithTimeout(ctx, liveSendTimeout)
		accepted := 0
		var err error
		if batching {
			var rejected int
			rejected, err = batchSender.SendBatch(sendContext, EngineZeek, sessionID, t.pending[:count])
			accepted = count - rejected
		} else {
			count = 1
			if err = sender.Send(sendContext, EngineZeek, sessionID, t.pending[0]); errors.Is(err, ErrEventRejected) {
				err = nil
			} else if err == nil {
				accepted = 1
			}
		}
		cancel()
		if err != nil {
			return delivered, err
		}
		delivered += accepted
		t.pending = t.pending[count:]
		t.pendingSz -= size
	}
	t.pending, t.pendingSz = nil, 0
	return delivered, nil
}

// Discard drops pending events, for a capture whose results were deleted.
func (t *zeekLogTail) Discard() { t.pending, t.pendingSz = nil, 0 }

func (t *zeekLogTail) Close() {
	for _, log := range t.logs {
		log.file.Close()
	}
	t.logs = map[string]*tailedLog{}
}

func openRegularNoFollow(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		unix.Close(descriptor)
		return nil, errors.New("open file descriptor")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("live analysis input is not a regular file")
	}
	return file, nil
}
