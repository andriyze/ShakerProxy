// Package testsession stores named, time-bounded test runs against one
// device ("Firmware 2.1 first boot"). A session is metadata only: it bounds a
// time window for reports and comparisons and optionally links the packet
// capture that ran alongside it. The store is a single bounded JSON document
// written atomically.
package testsession

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	Schema          = 1
	MaxSessions     = 2000
	MaxNameBytes    = 120
	MaxNotesBytes   = 4096
	MaxActorBytes   = 96
	MaxDeviceName   = 256
	DefaultLimit    = 50
	MaxLimit        = 500
	maxDocumentSize = 16 << 20
)

type State string

const (
	StateRunning State = "RUNNING"
	StateStopped State = "STOPPED"
)

var (
	idPattern        = regexp.MustCompile(`^ts-[a-f0-9]{24}$`)
	deviceIDPattern  = regexp.MustCompile(`^device-[a-f0-9]{32}$`)
	capturePattern   = regexp.MustCompile(`^capture-[a-f0-9]{32}$`)
	ErrNotFound      = errors.New("test session was not found")
	ErrInvalid       = errors.New("test session request is invalid")
	ErrStoreFull     = errors.New("test session store is full of running sessions")
	ErrStoreRejected = errors.New("test session store is unavailable or invalid")
)

// Session is one test run. JSON field names are part of the public API.
type Session struct {
	Schema           int        `json:"schema"`
	ID               string     `json:"id"`
	DeviceID         string     `json:"device_id"`
	DeviceName       string     `json:"device_name"`
	Name             string     `json:"name"`
	Notes            string     `json:"notes"`
	State            State      `json:"state"`
	StartedAt        time.Time  `json:"started_at"`
	EndedAt          *time.Time `json:"ended_at"`
	CaptureSessionID *string    `json:"capture_session_id"`
	CreatedBy        string     `json:"created_by"`
}

// End returns the session's end, or now when it is still running.
func (s Session) End(now time.Time) time.Time {
	if s.EndedAt != nil {
		return *s.EndedAt
	}
	return now
}

type StartInput struct {
	DeviceID   string
	DeviceName string
	Name       string
	Notes      string
	Actor      string
}

type Filter struct {
	DeviceID string
	State    State
	Limit    int
}

type Update struct {
	Name  *string
	Notes *string
}

// Store persists sessions to Path. One Store must own a path per process.
type Store struct {
	Path   string
	Now    func() time.Time
	Random func([]byte) (int, error)
	mu     sync.Mutex
}

type document struct {
	Schema   int       `json:"schema"`
	Sessions []Session `json:"sessions"`
}

func ValidID(id string) bool { return idPattern.MatchString(id) }

// Start creates a RUNNING session. Any other RUNNING session for the same
// device is stopped first and returned in stopped.
func (s *Store) Start(input StartInput) (Session, []Session, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Notes = strings.TrimSpace(input.Notes)
	input.DeviceName = boundedText(strings.TrimSpace(input.DeviceName), MaxDeviceName)
	if !deviceIDPattern.MatchString(input.DeviceID) || validText(input.Name, 1, MaxNameBytes) != nil || validNotes(input.Notes) != nil || validText(input.Actor, 1, MaxActorBytes) != nil {
		return Session{}, nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.read()
	if err != nil {
		return Session{}, nil, err
	}
	now := s.now()
	stopped := []Session{}
	for index := range doc.Sessions {
		item := &doc.Sessions[index]
		if item.DeviceID == input.DeviceID && item.State == StateRunning {
			stopSession(item, now)
			stopped = append(stopped, cloneSession(*item))
		}
	}
	id, err := s.newID(func(candidate string) bool { return findSession(doc.Sessions, candidate) >= 0 })
	if err != nil {
		return Session{}, nil, err
	}
	created := Session{
		Schema: Schema, ID: id, DeviceID: input.DeviceID, DeviceName: input.DeviceName, Name: input.Name,
		Notes: input.Notes, State: StateRunning, StartedAt: now, CreatedBy: input.Actor,
	}
	doc.Sessions = append(doc.Sessions, created)
	if err := prune(&doc); err != nil {
		return Session{}, nil, err
	}
	if err := s.write(doc); err != nil {
		return Session{}, nil, err
	}
	return cloneSession(created), stopped, nil
}

// AttachCapture links a packet capture to a session.
func (s *Store) AttachCapture(id, captureSessionID string) (Session, error) {
	if !ValidID(id) || !capturePattern.MatchString(captureSessionID) {
		return Session{}, ErrInvalid
	}
	return s.mutate(id, func(item *Session) error {
		value := captureSessionID
		item.CaptureSessionID = &value
		return nil
	})
}

func (s *Store) Get(id string) (Session, error) {
	if !ValidID(id) {
		return Session{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.read()
	if err != nil {
		return Session{}, err
	}
	index := findSession(doc.Sessions, id)
	if index < 0 {
		return Session{}, ErrNotFound
	}
	return cloneSession(doc.Sessions[index]), nil
}

// List returns matching sessions, newest first, and the total match count.
func (s *Store) List(filter Filter) ([]Session, int, error) {
	if filter.Limit == 0 {
		filter.Limit = DefaultLimit
	}
	if filter.Limit < 1 || filter.Limit > MaxLimit || filter.DeviceID != "" && !deviceIDPattern.MatchString(filter.DeviceID) || filter.State != "" && filter.State != StateRunning && filter.State != StateStopped {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.read()
	if err != nil {
		return nil, 0, err
	}
	matches := make([]Session, 0, min(len(doc.Sessions), filter.Limit))
	total := 0
	sorted := append([]Session(nil), doc.Sessions...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].StartedAt.Equal(sorted[j].StartedAt) {
			return sorted[i].StartedAt.After(sorted[j].StartedAt)
		}
		return sorted[i].ID > sorted[j].ID
	})
	for _, item := range sorted {
		if filter.DeviceID != "" && item.DeviceID != filter.DeviceID || filter.State != "" && item.State != filter.State {
			continue
		}
		total++
		if len(matches) < filter.Limit {
			matches = append(matches, cloneSession(item))
		}
	}
	return matches, total, nil
}

// Running returns the device's RUNNING session, if any.
func (s *Store) Running(deviceID string) (Session, bool, error) {
	items, _, err := s.List(Filter{DeviceID: deviceID, State: StateRunning, Limit: 1})
	if err != nil || len(items) == 0 {
		return Session{}, false, err
	}
	return items[0], true, nil
}

func (s *Store) Update(id string, update Update) (Session, error) {
	if !ValidID(id) {
		return Session{}, ErrNotFound
	}
	if update.Name == nil && update.Notes == nil {
		return Session{}, ErrInvalid
	}
	var name, notes string
	if update.Name != nil {
		name = strings.TrimSpace(*update.Name)
		if validText(name, 1, MaxNameBytes) != nil {
			return Session{}, ErrInvalid
		}
	}
	if update.Notes != nil {
		notes = strings.TrimSpace(*update.Notes)
		if validNotes(notes) != nil {
			return Session{}, ErrInvalid
		}
	}
	return s.mutate(id, func(item *Session) error {
		if update.Name != nil {
			item.Name = name
		}
		if update.Notes != nil {
			item.Notes = notes
		}
		return nil
	})
}

// Stop ends a RUNNING session. Stopping a STOPPED session returns it unchanged.
func (s *Store) Stop(id string) (Session, error) {
	if !ValidID(id) {
		return Session{}, ErrNotFound
	}
	now := s.now()
	return s.mutate(id, func(item *Session) error {
		if item.State == StateRunning {
			stopSession(item, now)
		}
		return nil
	})
}

// Delete removes session metadata. Captured traffic and packet files are
// not affected.
func (s *Store) Delete(id string) (Session, error) {
	if !ValidID(id) {
		return Session{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.read()
	if err != nil {
		return Session{}, err
	}
	index := findSession(doc.Sessions, id)
	if index < 0 {
		return Session{}, ErrNotFound
	}
	removed := doc.Sessions[index]
	doc.Sessions = append(doc.Sessions[:index], doc.Sessions[index+1:]...)
	if err := s.write(doc); err != nil {
		return Session{}, err
	}
	return removed, nil
}

func (s *Store) mutate(id string, change func(*Session) error) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.read()
	if err != nil {
		return Session{}, err
	}
	index := findSession(doc.Sessions, id)
	if index < 0 {
		return Session{}, ErrNotFound
	}
	item := doc.Sessions[index]
	if err := change(&item); err != nil {
		return Session{}, err
	}
	if err := item.Validate(); err != nil {
		return Session{}, err
	}
	doc.Sessions[index] = item
	if err := s.write(doc); err != nil {
		return Session{}, err
	}
	return cloneSession(item), nil
}

// prune keeps the store bounded by removing the oldest STOPPED sessions.
func prune(doc *document) error {
	excess := len(doc.Sessions) - MaxSessions
	if excess <= 0 {
		return nil
	}
	stopped := make([]int, 0, len(doc.Sessions))
	for index, item := range doc.Sessions {
		if item.State == StateStopped {
			stopped = append(stopped, index)
		}
	}
	if len(stopped) < excess {
		return ErrStoreFull
	}
	sort.SliceStable(stopped, func(i, j int) bool {
		left, right := doc.Sessions[stopped[i]], doc.Sessions[stopped[j]]
		if !left.StartedAt.Equal(right.StartedAt) {
			return left.StartedAt.Before(right.StartedAt)
		}
		return left.ID < right.ID
	})
	remove := make(map[int]struct{}, excess)
	for _, index := range stopped[:excess] {
		remove[index] = struct{}{}
	}
	kept := doc.Sessions[:0]
	for index, item := range doc.Sessions {
		if _, drop := remove[index]; !drop {
			kept = append(kept, item)
		}
	}
	doc.Sessions = kept
	return nil
}

func stopSession(item *Session, now time.Time) {
	ended := now
	if ended.Before(item.StartedAt) {
		ended = item.StartedAt
	}
	item.State = StateStopped
	item.EndedAt = &ended
}

// Validate checks one stored or returned session.
func (item Session) Validate() error {
	if item.Schema != Schema || !ValidID(item.ID) || !deviceIDPattern.MatchString(item.DeviceID) || validText(item.Name, 1, MaxNameBytes) != nil || validNotes(item.Notes) != nil || validText(item.CreatedBy, 1, MaxActorBytes) != nil || len(item.DeviceName) > MaxDeviceName || !utf8.ValidString(item.DeviceName) || item.StartedAt.IsZero() {
		return fmt.Errorf("%w: session identity or text is invalid", ErrStoreRejected)
	}
	switch item.State {
	case StateRunning:
		if item.EndedAt != nil {
			return fmt.Errorf("%w: running session has an end", ErrStoreRejected)
		}
	case StateStopped:
		if item.EndedAt == nil || item.EndedAt.Before(item.StartedAt) {
			return fmt.Errorf("%w: stopped session end is invalid", ErrStoreRejected)
		}
	default:
		return fmt.Errorf("%w: session state is invalid", ErrStoreRejected)
	}
	if item.CaptureSessionID != nil && !capturePattern.MatchString(*item.CaptureSessionID) {
		return fmt.Errorf("%w: capture link is invalid", ErrStoreRejected)
	}
	return nil
}

func findSession(items []Session, id string) int {
	for index := range items {
		if items[index].ID == id {
			return index
		}
	}
	return -1
}

func cloneSession(item Session) Session {
	if item.EndedAt != nil {
		ended := *item.EndedAt
		item.EndedAt = &ended
	}
	if item.CaptureSessionID != nil {
		captureID := *item.CaptureSessionID
		item.CaptureSessionID = &captureID
	}
	return item
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func (s *Store) newID(exists func(string) bool) (string, error) {
	random := s.Random
	if random == nil {
		random = rand.Read
	}
	for attempt := 0; attempt < 8; attempt++ {
		raw := make([]byte, 12)
		if _, err := random(raw); err != nil {
			return "", fmt.Errorf("%w: allocate identity", ErrStoreRejected)
		}
		id := "ts-" + hex.EncodeToString(raw)
		if !exists(id) {
			return id, nil
		}
	}
	return "", fmt.Errorf("%w: could not allocate a unique identity", ErrStoreRejected)
}

func (s *Store) read() (document, error) {
	if s.Path == "" || !filepath.IsAbs(s.Path) {
		return document{}, fmt.Errorf("%w: store path must be absolute", ErrStoreRejected)
	}
	info, err := os.Lstat(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return document{Schema: Schema, Sessions: []Session{}}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxDocumentSize {
		return document{}, fmt.Errorf("%w: store file is unsafe or too large", ErrStoreRejected)
	}
	data, err := os.ReadFile(s.Path)
	if err != nil || len(data) > maxDocumentSize {
		return document{}, fmt.Errorf("%w: store file is unreadable", ErrStoreRejected)
	}
	var doc document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return document{}, fmt.Errorf("%w: store document is malformed", ErrStoreRejected)
	}
	if doc.Schema != Schema || len(doc.Sessions) > MaxSessions {
		return document{}, fmt.Errorf("%w: store schema or size is invalid", ErrStoreRejected)
	}
	if doc.Sessions == nil {
		doc.Sessions = []Session{}
	}
	seen := make(map[string]struct{}, len(doc.Sessions))
	for _, item := range doc.Sessions {
		if err := item.Validate(); err != nil {
			return document{}, err
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return document{}, fmt.Errorf("%w: duplicate session identity", ErrStoreRejected)
		}
		seen[item.ID] = struct{}{}
	}
	return doc, nil
}

func (s *Store) write(doc document) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil || len(data) > maxDocumentSize {
		return fmt.Errorf("%w: store document exceeds its size limit", ErrStoreRejected)
	}
	directory := filepath.Dir(s.Path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".test-sessions-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.Path); err != nil {
		return err
	}
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

// validText checks a single-line value.
func validText(value string, minimum, maximum int) error {
	return checkText(value, minimum, maximum, false)
}

// validNotes checks free-form notes, which may span lines.
func validNotes(value string) error {
	return checkText(value, 0, MaxNotesBytes, true)
}

func checkText(value string, minimum, maximum int, multiline bool) error {
	if len(value) < minimum || len(value) > maximum || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return ErrInvalid
	}
	for _, character := range value {
		if multiline && (character == '\n' || character == '\t' || character == '\r') {
			continue
		}
		if character < 0x20 || character == 0x7f {
			return ErrInvalid
		}
	}
	return nil
}

func boundedText(value string, maximum int) string {
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "")
	}
	var builder strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			continue
		}
		if builder.Len()+utf8.RuneLen(character) > maximum {
			break
		}
		builder.WriteRune(character)
	}
	return strings.TrimSpace(builder.String())
}
