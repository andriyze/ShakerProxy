package syslogcollector

import (
	"sync"
	"time"
)

// bucket is a token-bucket rate limiter. A log source refilling faster than
// its rate is dropped rather than queued, so a chatty or hostile device
// cannot make the collector fall behind or use unbounded memory.
type bucket struct {
	mu       sync.Mutex
	rate     float64 // tokens per second
	capacity float64
	tokens   float64
	last     time.Time
}

func newBucket(rate float64, burst int) *bucket {
	capacity := float64(burst)
	if capacity < 1 {
		capacity = 1
	}
	return &bucket{rate: rate, capacity: capacity, tokens: capacity}
}

// allow reports whether one message may proceed at time now, consuming a token
// when it may.
func (b *bucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.last = now
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
