package vpn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// DefaultStatePath is root-only: it holds the server's private key.
const DefaultStatePath = "/var/lib/shakerproxy/gatewayd/vpn.json"

const maxStateBytes = 1 << 20

// Store persists the VPN state atomically with mode 0600.
type Store struct {
	Path string
}

// Load returns the saved state, or a new one (VPN mode off, fresh keys)
// that is saved first so the server key never changes afterwards.
func (s Store) Load() (State, error) {
	state, err := s.read()
	if errors.Is(err, os.ErrNotExist) {
		fresh, newErr := NewState()
		if newErr != nil {
			return State{}, newErr
		}
		if saveErr := s.Save(fresh); saveErr != nil {
			return State{}, saveErr
		}
		return fresh, nil
	}
	return state, err
}

func (s Store) read() (State, error) {
	file, err := os.Open(s.Path)
	if err != nil {
		return State{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return State{}, err
	}
	if !info.Mode().IsRegular() {
		return State{}, errors.New("the VPN state is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return State{}, fmt.Errorf("the VPN state %s must be readable by root only (mode 0600)", s.Path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return State{}, err
	}
	if len(raw) > maxStateBytes {
		return State{}, errors.New("the VPN state exceeds its size limit")
	}
	var state State
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return State{}, fmt.Errorf("decode the VPN state: %w", err)
	}
	if state.Peers == nil {
		state.Peers = []Peer{}
	}
	if err := state.Validate(); err != nil {
		return State{}, fmt.Errorf("the VPN state is invalid: %w", err)
	}
	return state, nil
}

// Save validates and atomically replaces the state.
func (s Store) Save(state State) error {
	if state.Peers == nil {
		state.Peers = []Peer{}
	}
	if err := state.Validate(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(s.Path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".vpn-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
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
