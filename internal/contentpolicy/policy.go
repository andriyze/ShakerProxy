// Package contentpolicy controls whether successfully intercepted HTTP traffic
// retains bounded decrypted headers/body previews. It is intentionally local
// sensor state and is separate from whether TLS interception itself is enabled.
package contentpolicy

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

const (
	SchemaVersion  = 1
	maxPolicyBytes = 16 << 10
)

var ErrRevisionConflict = errors.New("HTTP content policy revision changed")

type Policy struct {
	Schema             int       `json:"schema"`
	Revision           uint64    `json:"revision"`
	CaptureHTTPContent bool      `json:"capture_http_content"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
	UpdatedBy          string    `json:"updated_by,omitempty"`
}

type Store struct {
	Path string
	Now  func() time.Time
	mu   sync.Mutex
}

func Default() Policy {
	// Preserve the historical Community behavior until an administrator
	// explicitly disables plaintext retention. Interception state remains a
	// separate traffic-policy control.
	return Policy{Schema: SchemaVersion, Revision: 1, CaptureHTTPContent: true}
}

func (s *Store) Load() (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *Store) Apply(expectedRevision uint64, capture bool, actor string) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expectedRevision == 0 || len(actor) < 1 || len(actor) > 128 {
		return Policy{}, errors.New("HTTP content policy mutation is invalid")
	}
	current, err := s.load()
	if err != nil {
		return Policy{}, err
	}
	if current.Revision != expectedRevision {
		return Policy{}, ErrRevisionConflict
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	next := Policy{Schema: SchemaVersion, Revision: current.Revision + 1, CaptureHTTPContent: capture, UpdatedAt: now, UpdatedBy: actor}
	if err := s.save(next); err != nil {
		return Policy{}, err
	}
	return next, nil
}

func (s *Store) load() (Policy, error) {
	if s == nil || s.Path == "" || !filepath.IsAbs(s.Path) {
		return Policy{}, errors.New("HTTP content policy path is invalid")
	}
	info, err := os.Lstat(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("inspect HTTP content policy: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxPolicyBytes {
		return Policy{}, errors.New("HTTP content policy is not a bounded regular file")
	}
	file, err := os.Open(s.Path)
	if err != nil {
		return Policy{}, fmt.Errorf("open HTTP content policy: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() || opened.ModTime() != info.ModTime() {
		return Policy{}, errors.New("HTTP content policy changed while it was opened")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
	if err != nil || len(contents) == 0 || len(contents) > maxPolicyBytes {
		return Policy{}, errors.New("HTTP content policy could not be read within its bound")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() || after.ModTime() != opened.ModTime() {
		return Policy{}, errors.New("HTTP content policy changed while it was read")
	}
	var policy Policy
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("decode HTTP content policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Policy{}, errors.New("HTTP content policy contains trailing JSON")
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func (policy Policy) Validate() error {
	if policy.Schema != SchemaVersion || policy.Revision == 0 || len(policy.UpdatedBy) > 128 {
		return errors.New("HTTP content policy has invalid schema or bounds")
	}
	if policy.Revision == 1 && policy.UpdatedAt.IsZero() && policy.UpdatedBy == "" {
		return nil
	}
	if policy.UpdatedAt.IsZero() || policy.UpdatedBy == "" {
		return errors.New("HTTP content policy mutation provenance is incomplete")
	}
	return nil
}

func (s *Store) save(policy Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	contents, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("encode HTTP content policy: %w", err)
	}
	contents = append(contents, '\n')
	if len(contents) > maxPolicyBytes {
		return errors.New("HTTP content policy exceeds its storage bound")
	}
	directory := filepath.Dir(s.Path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("create HTTP content policy directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".http-content-policy-*")
	if err != nil {
		return fmt.Errorf("create HTTP content policy temporary file: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
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
		return fmt.Errorf("replace HTTP content policy: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}
