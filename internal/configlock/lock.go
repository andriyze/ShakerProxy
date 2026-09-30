package configlock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DefaultPath      = "/run/lock/shakerproxy/config.lock"
	maxMetadataBytes = 8 << 10
	metadataSchema   = 1
	acquisitionPoll  = 25 * time.Millisecond
)

type Category string

const (
	CategoryNetwork   Category = "network"
	CategoryDNS       Category = "dns"
	CategoryInstall   Category = "install"
	CategoryUpdate    Category = "update"
	CategoryRepair    Category = "repair"
	CategoryRollback  Category = "rollback"
	CategoryRestore   Category = "restore"
	CategoryCapture   Category = "capture"
	CategoryRetention Category = "retention"
	CategoryRuleset   Category = "ruleset"
	CategoryUninstall Category = "uninstall"
)

var (
	operationPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{7,95}$`)
	actorPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,95}$`)
	ErrBusy          = errors.New("appliance configuration is locked")
)

type Request struct {
	OperationID string
	Category    Category
	Actor       string
}

type Record struct {
	Schema      int       `json:"schema"`
	OperationID string    `json:"operation_id"`
	Category    Category  `json:"category"`
	Actor       string    `json:"actor"`
	PID         int       `json:"pid"`
	StartedAt   time.Time `json:"started_at"`
}

type Status struct {
	Active bool    `json:"active"`
	Record *Record `json:"record,omitempty"`
	Stale  bool    `json:"stale_metadata,omitempty"`
}

type BusyError struct {
	Current *Record
}

func (e *BusyError) Error() string {
	if e.Current == nil {
		return ErrBusy.Error()
	}
	return fmt.Sprintf("%s by %s operation %s", ErrBusy, e.Current.Category, e.Current.OperationID)
}

func (e *BusyError) Unwrap() error { return ErrBusy }

type Manager struct {
	Path string
	Now  func() time.Time
}

type Guard struct {
	file       *os.File
	manager    Manager
	record     Record
	releaseErr error
	once       sync.Once
}

func (m Manager) Acquire(ctx context.Context, request Request) (*Guard, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	path := m.path()
	if err := ensureLockDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open appliance configuration lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open appliance configuration lock")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("appliance configuration lock is not a regular file")
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("acquire appliance configuration lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			current, _ := m.readRecord()
			return nil, &BusyError{Current: current}
		case <-time.After(acquisitionPoll):
		}
	}
	record := Record{Schema: metadataSchema, OperationID: request.OperationID, Category: request.Category, Actor: request.Actor, PID: os.Getpid(), StartedAt: m.now()}
	if err := m.writeRecord(record); err != nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = file.Close()
		return nil, err
	}
	return &Guard{file: file, manager: m, record: record}, nil
}

func (m Manager) Inspect() (Status, error) {
	path := m.path()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return Status{}, nil
	}
	if err != nil {
		return Status{}, fmt.Errorf("open appliance configuration lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return Status{}, errors.New("appliance configuration lock is not a regular file")
	}
	locked := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	if locked == nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		record, readErr := m.readRecord()
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return Status{}, readErr
		}
		return Status{Record: record, Stale: record != nil}, nil
	}
	if !errors.Is(locked, unix.EWOULDBLOCK) && !errors.Is(locked, unix.EAGAIN) {
		return Status{}, fmt.Errorf("inspect appliance configuration lock: %w", locked)
	}
	record, err := m.readRecord()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Status{}, err
	}
	return Status{Active: true, Record: record}, nil
}

func (g *Guard) Release() error {
	if g == nil {
		return nil
	}
	g.once.Do(func() {
		if current, err := g.manager.readRecord(); err == nil && current.OperationID == g.record.OperationID && current.PID == g.record.PID {
			if err := os.Remove(g.manager.metadataPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
				g.releaseErr = err
			}
		}
		if err := unix.Flock(int(g.file.Fd()), unix.LOCK_UN); err != nil && g.releaseErr == nil {
			g.releaseErr = err
		}
		if err := g.file.Close(); err != nil && g.releaseErr == nil {
			g.releaseErr = err
		}
	})
	return g.releaseErr
}

func (r Request) Validate() error {
	if !operationPattern.MatchString(r.OperationID) || !actorPattern.MatchString(r.Actor) || !validCategory(r.Category) {
		return errors.New("appliance configuration lock request is invalid")
	}
	return nil
}

func (r Record) Validate() error {
	request := Request{OperationID: r.OperationID, Category: r.Category, Actor: r.Actor}
	if r.Schema != metadataSchema || request.Validate() != nil || r.PID < 1 || r.StartedAt.IsZero() {
		return errors.New("appliance configuration lock metadata is invalid")
	}
	return nil
}

func validCategory(category Category) bool {
	switch category {
	case CategoryNetwork, CategoryDNS, CategoryInstall, CategoryUpdate, CategoryRepair, CategoryRollback, CategoryRestore, CategoryCapture, CategoryRetention, CategoryRuleset, CategoryUninstall:
		return true
	default:
		return false
	}
}

func ensureLockDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create appliance configuration lock directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("appliance configuration lock directory is unsafe")
	}
	return nil
}

func (m Manager) writeRecord(record Record) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	file, err := os.CreateTemp(filepath.Dir(m.metadataPath()), filepath.Base(m.metadataPath())+".tmp.")
	if err != nil {
		return fmt.Errorf("create appliance configuration lock metadata: %w", err)
	}
	temporary := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	cleanup := func() { _ = os.Remove(temporary) }
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(temporary, m.metadataPath()); err != nil {
		cleanup()
		return fmt.Errorf("publish appliance configuration lock metadata: %w", err)
	}
	return nil
}

func (m Manager) readRecord() (*Record, error) {
	fd, err := unix.Open(m.metadataPath(), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), m.metadataPath())
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxMetadataBytes {
		return nil, errors.New("appliance configuration lock metadata is unsafe")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxMetadataBytes+1))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return nil, errors.New("appliance configuration lock metadata is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("appliance configuration lock metadata has trailing data")
	}
	if err := record.Validate(); err != nil {
		return nil, err
	}
	return &record, nil
}

func (m Manager) path() string {
	if m.Path != "" {
		return m.Path
	}
	return DefaultPath
}

func (m Manager) metadataPath() string { return m.path() + ".json" }

func (m Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}
