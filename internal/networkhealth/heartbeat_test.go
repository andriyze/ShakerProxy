package networkhealth

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	heartbeatApplyID  = "apply-0123456789abcdef0123456789abcdef"
	heartbeatPlanHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestHeartbeatGateRequiresExactIdentityAndToken(t *testing.T) {
	now := time.Unix(9000, 0)
	gate := &HeartbeatGate{Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)), Now: func() time.Time { return now }}
	token, err := gate.Open(heartbeatApplyID, heartbeatPlanHash, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || strings.Contains(token, heartbeatPlanHash) {
		t.Fatal("heartbeat token was not opaque")
	}
	if err := gate.Signal(heartbeatApplyID, heartbeatPlanHash, token+"x"); err == nil {
		t.Fatal("wrong heartbeat token was accepted")
	}
	if err := gate.Signal(heartbeatApplyID, strings.Repeat("f", 64), token); err == nil {
		t.Fatal("wrong plan hash was accepted")
	}
	if err := gate.Signal(heartbeatApplyID, heartbeatPlanHash, token); err != nil {
		t.Fatal(err)
	}
	if err := gate.Wait(context.Background(), heartbeatApplyID, heartbeatPlanHash); err != nil {
		t.Fatal(err)
	}
	if err := gate.Signal(heartbeatApplyID, heartbeatPlanHash, token); err != nil {
		t.Fatalf("matching heartbeat retry was not idempotent: %v", err)
	}
}

func TestHeartbeatGateCancellationAndRestartFailClosed(t *testing.T) {
	now := time.Now()
	gate := &HeartbeatGate{Random: bytes.NewReader(bytes.Repeat([]byte{0x24}, 32))}
	if _, err := gate.Open(heartbeatApplyID, heartbeatPlanHash, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gate.Wait(ctx, heartbeatApplyID, heartbeatPlanHash); err == nil {
		t.Fatal("canceled management channel was treated as healthy")
	}
	restarted := &HeartbeatGate{}
	if err := restarted.Wait(context.Background(), heartbeatApplyID, heartbeatPlanHash); err == nil {
		t.Fatal("daemon restart preserved an unproven management heartbeat")
	}
}

func TestHeartbeatGateRejectsExpiredAndDuplicateChannels(t *testing.T) {
	now := time.Unix(9000, 0)
	gate := &HeartbeatGate{Random: bytes.NewReader(bytes.Repeat([]byte{0x10}, 64)), Now: func() time.Time { return now }}
	token, err := gate.Open(heartbeatApplyID, heartbeatPlanHash, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Open(heartbeatApplyID, heartbeatPlanHash, now.Add(time.Minute)); err == nil {
		t.Fatal("duplicate heartbeat channel was opened")
	}
	now = now.Add(2 * time.Minute)
	if err := gate.Signal(heartbeatApplyID, heartbeatPlanHash, token); err == nil {
		t.Fatal("expired heartbeat was accepted")
	}
}

func TestHeartbeatSignalIsConcurrencySafe(t *testing.T) {
	now := time.Unix(9000, 0)
	gate := &HeartbeatGate{Random: bytes.NewReader(bytes.Repeat([]byte{0x7f}, 32)), Now: func() time.Time { return now }}
	token, err := gate.Open(heartbeatApplyID, heartbeatPlanHash, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := gate.Signal(heartbeatApplyID, heartbeatPlanHash, token); err != nil {
				t.Errorf("concurrent heartbeat failed: %v", err)
			}
		}()
	}
	wait.Wait()
}

func TestHeartbeatGateAcceptsAValidatedCallerDerivedToken(t *testing.T) {
	now := time.Unix(9000, 0)
	gate := &HeartbeatGate{Now: func() time.Time { return now }}
	token := "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
	if err := gate.OpenWithToken(heartbeatApplyID, heartbeatPlanHash, token, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := gate.Signal(heartbeatApplyID, heartbeatPlanHash, token); err != nil {
		t.Fatal(err)
	}
	if err := gate.OpenWithToken("bad", heartbeatPlanHash, token, now.Add(time.Minute)); err == nil {
		t.Fatal("invalid caller-derived token identity was accepted")
	}
	if err := gate.OpenWithToken("apply-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", heartbeatPlanHash, "short", now.Add(time.Minute)); err == nil {
		t.Fatal("invalid caller-derived token was accepted")
	}
}
