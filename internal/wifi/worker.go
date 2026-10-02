package wifi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Default paths of the Wi-Fi worker.
const (
	DefaultRingDirectory = "/var/lib/shakerproxy/wifi/ring"
	DefaultScopePath     = "/var/lib/shakerproxy/wifi/scope.json"
	DefaultStatePath     = "/var/lib/shakerproxy/wifi-worker/state.json"
	// RingFilePrefix is the dumpcap ring name: wifi_00001_20261002120000.pcapng.
	RingFilePrefix = "wifi"

	workerPoll        = time.Second
	scopeReload       = 5 * time.Second
	stateSaveInterval = 30 * time.Second
	maxRingFiles      = 512
	maxStateBytes     = 4 << 20
)

var ringFilePattern = regexp.MustCompile(`^` + RingFilePrefix + `_([0-9]{5,9})_[0-9]{14}\.pcapng$`)

// Sink receives the events the worker produces.
type Sink interface {
	Publish(Event)
}

// Worker follows the Wi-Fi ring buffer dumpcap writes and turns its frames
// into events. It reads the newest file again each pass and skips the
// packets it already read, so events appear within about a second.
type Worker struct {
	RingDirectory string
	ScopePath     string
	StatePath     string
	Sink          Sink
	Logger        *slog.Logger
	Now           func() time.Time

	observer *Observer
	scopeMod time.Time
	scopeAt  time.Time
	done     map[string]bool
	progress map[string]int
	failed   map[string]bool
	savedAt  time.Time
	hasScope bool
}

type workerState struct {
	Schema   int                  `json:"schema"`
	Done     []string             `json:"done"`
	Progress map[string]int       `json:"progress"`
	Learned  map[string]time.Time `json:"learned"`
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

func (w *Worker) init() {
	if w.observer != nil {
		return
	}
	// Without a scope nothing is recorded: the observer starts closed.
	w.observer = NewObserver(nil)
	w.done, w.progress, w.failed = map[string]bool{}, map[string]int{}, map[string]bool{}
	w.loadState()
}

// Run follows the ring until ctx ends.
func (w *Worker) Run(ctx context.Context) error {
	if w.RingDirectory == "" || w.ScopePath == "" || w.Sink == nil {
		return errors.New("Wi-Fi worker is not configured")
	}
	w.init()
	ticker := time.NewTicker(workerPoll)
	defer ticker.Stop()
	for {
		w.Pass(ctx)
		select {
		case <-ctx.Done():
			w.saveState()
			return nil
		case <-ticker.C:
		}
	}
}

// Pass reads what is new in the ring and publishes the events.
func (w *Worker) Pass(ctx context.Context) {
	w.init()
	now := w.now()
	w.reloadScope(now)
	files := w.ringFiles()
	present := map[string]bool{}
	for index, name := range files {
		present[name] = true
		if w.done[name] || w.failed[name] {
			continue
		}
		newest := index == len(files)-1
		progress, err := w.readFile(ctx, name)
		if err != nil {
			if !newest {
				// A closed file that does not parse is skipped, once.
				w.failed[name] = true
				if w.Logger != nil {
					w.Logger.Warn("Wi-Fi capture file could not be read", "file", name, "error", err)
				}
			}
			continue
		}
		w.progress[name] = progress.Packets
		if progress.Complete && !newest {
			w.done[name] = true
			delete(w.progress, name)
		}
	}
	for name := range w.done {
		if !present[name] {
			delete(w.done, name)
		}
	}
	for name := range w.progress {
		if !present[name] {
			delete(w.progress, name)
		}
	}
	for name := range w.failed {
		if !present[name] {
			delete(w.failed, name)
		}
	}
	w.observer.Flush(now)
	for _, event := range w.observer.Drain() {
		w.Sink.Publish(event)
	}
	if now.Sub(w.savedAt) >= stateSaveInterval {
		w.saveState()
	}
}

func (w *Worker) readFile(ctx context.Context, name string) (FileProgress, error) {
	file, err := os.Open(filepath.Join(w.RingDirectory, name))
	if err != nil {
		return FileProgress{}, err
	}
	defer file.Close()
	return ObserveFile(ctx, file, w.observer, w.progress[name])
}

// ringFiles lists the ring's capture files, oldest first.
func (w *Worker) ringFiles() []string {
	entries, err := os.ReadDir(w.RingDirectory)
	if err != nil {
		return nil
	}
	type ringFile struct {
		name   string
		number int
	}
	files := []ringFile{}
	for _, entry := range entries {
		match := ringFilePattern.FindStringSubmatch(entry.Name())
		if match == nil || !entry.Type().IsRegular() {
			continue
		}
		number, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		files = append(files, ringFile{name: entry.Name(), number: number})
	}
	sort.Slice(files, func(left, right int) bool { return files[left].number < files[right].number })
	if len(files) > maxRingFiles {
		files = files[len(files)-maxRingFiles:]
	}
	names := make([]string, len(files))
	for index, file := range files {
		names[index] = file.name
	}
	return names
}

// reloadScope rereads the scope file when it changed. A missing or invalid
// scope records nothing.
func (w *Worker) reloadScope(now time.Time) {
	if w.hasScope && now.Sub(w.scopeAt) < scopeReload {
		return
	}
	w.scopeAt = now
	info, err := os.Stat(w.ScopePath)
	if err != nil {
		if w.hasScope && w.Logger != nil {
			w.Logger.Warn("Wi-Fi scope is unavailable; nothing is recorded until it returns", "error", err)
		}
		w.observer.SetScope(nil)
		w.hasScope, w.scopeMod = false, time.Time{}
		return
	}
	if w.hasScope && info.ModTime().Equal(w.scopeMod) {
		return
	}
	file, err := ReadScopeFile(w.ScopePath)
	if err != nil {
		if w.Logger != nil {
			w.Logger.Warn("Wi-Fi scope is invalid; nothing is recorded until it is fixed", "error", err)
		}
		w.observer.SetScope(nil)
		w.hasScope, w.scopeMod = false, time.Time{}
		return
	}
	w.observer.SetScope(CompileScope(file))
	w.hasScope, w.scopeMod = true, info.ModTime()
	if w.Logger != nil {
		w.Logger.Info("Wi-Fi scope loaded", "lab_access_points", len(file.LabBSSIDs), "lab_devices", len(file.LabMACs), "nearby", file.Nearby)
	}
}

func (w *Worker) loadState() {
	if w.StatePath == "" {
		return
	}
	data, err := os.ReadFile(w.StatePath)
	if err != nil || len(data) > maxStateBytes {
		return
	}
	var state workerState
	if json.Unmarshal(data, &state) != nil || state.Schema != 1 {
		return
	}
	for _, name := range state.Done {
		if ringFilePattern.MatchString(name) && len(w.done) < maxRingFiles {
			w.done[name] = true
		}
	}
	for name, packets := range state.Progress {
		if ringFilePattern.MatchString(name) && packets >= 0 && len(w.progress) < maxRingFiles {
			w.progress[name] = packets
		}
	}
	w.observer.Remember(state.Learned, w.now())
}

func (w *Worker) saveState() {
	w.savedAt = w.now()
	if w.StatePath == "" || w.observer == nil {
		return
	}
	state := workerState{Schema: 1, Done: []string{}, Progress: w.progress, Learned: w.observer.Learned()}
	for name := range w.done {
		state.Done = append(state.Done, name)
	}
	sort.Strings(state.Done)
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	temporary := w.StatePath + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		if w.Logger != nil {
			w.Logger.Warn("Wi-Fi worker state could not be saved", "error", err)
		}
		return
	}
	_ = os.Rename(temporary, w.StatePath)
}
