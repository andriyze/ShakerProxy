package notify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// LoadConfig reads the configuration, returning the default inert config when
// the file does not exist yet.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultConfig(), nil
	}
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}
	if config.Schema == 0 {
		config.Schema = ConfigSchema
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// SaveConfig writes the configuration atomically, root-and-group readable.
func SaveConfig(path string, config Config) error {
	config.Schema = ConfigSchema
	if err := config.Validate(); err != nil {
		return err
	}
	return writeAtomic(path, ".notify-config-*", config, 0o640)
}

// NotificationLog is the bounded, newest-first in-app notification list.
type NotificationLog struct {
	Schema        int            `json:"schema"`
	UpdatedAt     time.Time      `json:"updated_at,omitzero"`
	Notifications []Notification `json:"notifications"`
}

// MaxStored bounds the in-app list.
const MaxStored = 200

// LoadLog reads the in-app list, returning an empty list when absent.
func LoadLog(path string) (NotificationLog, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NotificationLog{Schema: ConfigSchema}, nil
	}
	if err != nil {
		return NotificationLog{}, err
	}
	var log NotificationLog
	if err := json.Unmarshal(data, &log); err != nil {
		return NotificationLog{}, err
	}
	return log, nil
}

// logLocks serializes the read-modify-write of each log file. writeAtomic
// makes one write atomic, but the evaluator appending while a user marks
// everything read would otherwise lose whichever rename came first: a new
// alert or the read state.
var logLocks sync.Map // path -> *sync.Mutex

func lockLog(path string) func() {
	value, _ := logLocks.LoadOrStore(filepath.Clean(path), &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return mutex.Unlock
}

// Append adds notifications (newest first) and keeps at most MaxStored,
// writing the list atomically. The in-app channel stores every delivered
// notification regardless of which channels it also went to.
func AppendLog(path string, add []Notification, now time.Time) error {
	defer lockLog(path)()
	log, err := LoadLog(path)
	if err != nil {
		return err
	}
	stored := make([]Notification, 0, len(add))
	for _, n := range add {
		n.Read = false
		stored = append(stored, n)
	}
	log.Notifications = append(stored, log.Notifications...)
	if len(log.Notifications) > MaxStored {
		log.Notifications = log.Notifications[:MaxStored]
	}
	log.Schema = ConfigSchema
	log.UpdatedAt = now.UTC()
	return writeAtomic(path, ".notify-log-*", log, 0o640)
}

// MarkRead marks the given ids read, or all when ids is empty, and reports how
// many changed.
func MarkRead(path string, ids []string) (int, error) {
	defer lockLog(path)()
	log, err := LoadLog(path)
	if err != nil {
		return 0, err
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	changed := 0
	for index := range log.Notifications {
		if log.Notifications[index].Read {
			continue
		}
		if len(want) == 0 || want[log.Notifications[index].ID] {
			log.Notifications[index].Read = true
			changed++
		}
	}
	if changed == 0 {
		return 0, nil
	}
	log.Schema = ConfigSchema
	if err := writeAtomic(path, ".notify-log-*", log, 0o640); err != nil {
		return 0, err
	}
	return changed, nil
}

// Unread counts the unread notifications in a log.
func (l NotificationLog) Unread() int {
	count := 0
	for _, n := range l.Notifications {
		if !n.Read {
			count++
		}
	}
	return count
}

// Recent returns at most limit notifications, newest first.
func (l NotificationLog) Recent(limit int) []Notification {
	notifications := append([]Notification(nil), l.Notifications...)
	sort.SliceStable(notifications, func(i, j int) bool { return notifications[i].CreatedAt.After(notifications[j].CreatedAt) })
	if limit > 0 && len(notifications) > limit {
		notifications = notifications[:limit]
	}
	return notifications
}

// EvalState is what the evaluator remembers between passes and restarts:
// when each rule+subject last fired, and which devices were already known.
// Without it a restart re-sends every still-active condition and could
// announce every present device as new.
type EvalState struct {
	Schema    int                  `json:"schema"`
	Seeded    bool                 `json:"seeded"`
	LastFired map[string]time.Time `json:"last_fired"`
	Known     []string             `json:"known_devices"`
}

// MaxKnownDevices bounds the remembered device list.
const MaxKnownDevices = 4096

// LoadEvalState reads the evaluator state, returning an empty state when the
// file is absent.
func LoadEvalState(path string) (EvalState, error) {
	state := EvalState{Schema: ConfigSchema, LastFired: map[string]time.Time{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return EvalState{Schema: ConfigSchema, LastFired: map[string]time.Time{}}, err
	}
	if state.LastFired == nil {
		state.LastFired = map[string]time.Time{}
	}
	return state, nil
}

// SaveEvalState writes the evaluator state atomically.
func SaveEvalState(path string, state EvalState) error {
	state.Schema = ConfigSchema
	sort.Strings(state.Known)
	if len(state.Known) > MaxKnownDevices {
		state.Known = state.Known[:MaxKnownDevices]
	}
	return writeAtomic(path, ".notify-state-*", state, 0o640)
}

func writeAtomic(path, pattern string, value any, mode os.FileMode) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
