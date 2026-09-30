package trafficpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxPolicyBytes = 256 << 10

type Document struct {
	Schema    int       `json:"schema"`
	Policy    Policy    `json:"policy"`
	Digest    string    `json:"digest"`
	AppliedAt time.Time `json:"applied_at"`
	Previous  *Policy   `json:"previous,omitempty"`
}

type Store struct {
	Path string
	Now  func() time.Time
	mu   sync.Mutex
}

func (s *Store) Load() (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) Apply(policy Policy, expectedRevision uint64) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized, err := Normalize(policy)
	if err != nil {
		return Document{}, err
	}
	current, err := s.loadLocked()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Document{}, err
	}
	if current.Policy.Revision != expectedRevision {
		return Document{}, fmt.Errorf("traffic policy revision conflict: current %d, expected %d", current.Policy.Revision, expectedRevision)
	}
	if normalized.Revision <= current.Policy.Revision {
		return Document{}, errors.New("traffic policy revision must increase")
	}
	digest, err := Digest(normalized)
	if err != nil {
		return Document{}, err
	}
	var previous *Policy
	if current.Policy.Revision != 0 {
		copy := current.Policy
		previous = &copy
	}
	document := Document{Schema: SchemaVersion, Policy: normalized, Digest: digest, AppliedAt: s.now(), Previous: previous}
	if err := s.writeLocked(document); err != nil {
		return Document{}, err
	}
	return document, nil
}

func (s *Store) Rollback(expectedRevision uint64) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.loadLocked()
	if err != nil {
		return Document{}, err
	}
	if current.Policy.Revision != expectedRevision {
		return Document{}, fmt.Errorf("traffic policy revision conflict: current %d, expected %d", current.Policy.Revision, expectedRevision)
	}
	if current.Previous == nil {
		return Document{}, errors.New("no previous traffic policy is retained")
	}
	previous := *current.Previous
	previous.Revision = current.Policy.Revision + 1
	digest, err := Digest(previous)
	if err != nil {
		return Document{}, err
	}
	oldCurrent := current.Policy
	document := Document{Schema: SchemaVersion, Policy: previous, Digest: digest, AppliedAt: s.now(), Previous: &oldCurrent}
	if err := s.writeLocked(document); err != nil {
		return Document{}, err
	}
	return document, nil
}

func (s *Store) loadLocked() (Document, error) {
	if s.Path == "" {
		return Document{}, errors.New("traffic policy store path is required")
	}
	info, err := os.Lstat(s.Path)
	if err != nil {
		return Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPolicyBytes {
		return Document{}, errors.New("traffic policy document is not a bounded regular file")
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return Document{}, err
	}
	var document Document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, errors.New("traffic policy document is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Document{}, errors.New("traffic policy document contains trailing data")
	}
	if document.Schema != SchemaVersion || document.AppliedAt.IsZero() {
		return Document{}, errors.New("traffic policy document metadata is invalid")
	}
	normalized, err := Normalize(document.Policy)
	if err != nil {
		return Document{}, err
	}
	digest, err := Digest(normalized)
	if err != nil || digest != document.Digest {
		return Document{}, errors.New("traffic policy document digest mismatch")
	}
	document.Policy = normalized
	return document, nil
}

func (s *Store) writeLocked(document Document) error {
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxPolicyBytes {
		return errors.New("traffic policy document exceeds maximum size")
	}
	directory := filepath.Dir(s.Path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".traffic-policy-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o640); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
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
	if dir, err := os.Open(directory); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
