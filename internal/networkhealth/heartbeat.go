package networkhealth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const maxHeartbeatEntries = 64

type heartbeatEntry struct {
	planHash    string
	tokenDigest [sha256.Size]byte
	deadline    time.Time
	signal      chan struct{}
	signaled    bool
}

type HeartbeatGate struct {
	mu      sync.Mutex
	entries map[string]*heartbeatEntry
	Random  io.Reader
	Now     func() time.Time
}

func (g *HeartbeatGate) Open(applyID, planHash string, deadline time.Time) (string, error) {
	random := g.Random
	if random == nil {
		random = rand.Reader
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", errors.New("generate management heartbeat token")
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if err := g.OpenWithToken(applyID, planHash, token, deadline); err != nil {
		return "", err
	}
	return token, nil
}

func (g *HeartbeatGate) OpenWithToken(applyID, planHash, token string, deadline time.Time) error {
	if !networktransaction.ValidApplyID(applyID) || !networktransaction.ValidPlanHash(planHash) {
		return errors.New("management heartbeat identity is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return errors.New("management heartbeat token is invalid")
	}
	now := g.now()
	if !deadline.After(now) || deadline.Sub(now) > networktransaction.MaxRollbackWindow {
		return errors.New("management heartbeat deadline is invalid")
	}
	digest := sha256.Sum256([]byte(token))

	g.mu.Lock()
	defer g.mu.Unlock()
	g.initializeLocked()
	g.pruneLocked(now)
	if _, exists := g.entries[applyID]; exists {
		return errors.New("management heartbeat channel is already open")
	}
	if len(g.entries) >= maxHeartbeatEntries {
		return errors.New("too many management heartbeat channels are open")
	}
	g.entries[applyID] = &heartbeatEntry{planHash: planHash, tokenDigest: digest, deadline: deadline.UTC(), signal: make(chan struct{})}
	return nil
}

func (g *HeartbeatGate) Signal(applyID, planHash, token string) error {
	if !networktransaction.ValidApplyID(applyID) || !networktransaction.ValidPlanHash(planHash) || len(token) == 0 || len(token) > 256 {
		return errors.New("management heartbeat is invalid")
	}
	provided := sha256.Sum256([]byte(token))
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initializeLocked()
	entry, exists := g.entries[applyID]
	if !exists || entry.planHash != planHash || !now.Before(entry.deadline) || subtle.ConstantTimeCompare(provided[:], entry.tokenDigest[:]) != 1 {
		return errors.New("management heartbeat was rejected")
	}
	if !entry.signaled {
		entry.signaled = true
		close(entry.signal)
	}
	return nil
}

func (g *HeartbeatGate) Wait(ctx context.Context, applyID, planHash string) error {
	if !networktransaction.ValidApplyID(applyID) || !networktransaction.ValidPlanHash(planHash) {
		return errors.New("management heartbeat identity is invalid")
	}
	now := g.now()
	g.mu.Lock()
	g.initializeLocked()
	entry, exists := g.entries[applyID]
	if !exists || entry.planHash != planHash {
		g.mu.Unlock()
		return errors.New("management heartbeat channel is unavailable")
	}
	if entry.signaled {
		g.mu.Unlock()
		return nil
	}
	deadline := entry.deadline
	signal := entry.signal
	g.mu.Unlock()
	if !deadline.After(now) {
		return errors.New("management heartbeat deadline elapsed")
	}
	timer := time.NewTimer(deadline.Sub(now))
	defer timer.Stop()
	select {
	case <-signal:
		return nil
	case <-timer.C:
		return errors.New("management heartbeat deadline elapsed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *HeartbeatGate) Close(applyID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.entries != nil {
		delete(g.entries, applyID)
	}
}

func (g *HeartbeatGate) initializeLocked() {
	if g.entries == nil {
		g.entries = map[string]*heartbeatEntry{}
	}
}

func (g *HeartbeatGate) pruneLocked(now time.Time) {
	for applyID, entry := range g.entries {
		if !entry.deadline.After(now) {
			delete(g.entries, applyID)
		}
	}
}

func (g *HeartbeatGate) now() time.Time {
	if g.Now != nil {
		return g.Now().UTC()
	}
	return time.Now().UTC()
}
