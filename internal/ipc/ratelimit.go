package ipc

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// bucket tracks tokens for a single UID using a token-bucket algorithm.
type bucket struct {
	tokens     float64
	lastRefill time.Time
}

// RateLimiter enforces per-UID request rate limits and a global concurrent
// authentication limit. It is safe for concurrent use.
type RateLimiter struct {
	// Per-UID token bucket parameters
	maxTokens  float64 // burst size (== MaxRequestsPerMinute)
	refillRate float64 // tokens per second

	mu      sync.Mutex
	buckets map[uint32]*bucket

	// Concurrent auth semaphore
	maxConcurrentAuths int32
	concurrentAuths    atomic.Int32

	// Cleanup goroutine lifecycle
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewRateLimiter creates a RateLimiter. If maxRequestsPerMinute or
// maxConcurrentAuths is <= 0, that particular limit is disabled (always
// allows). A background goroutine evicts stale UID entries every 5 minutes.
func NewRateLimiter(maxRequestsPerMinute, maxConcurrentAuths int) *RateLimiter {
	rl := &RateLimiter{
		maxTokens:          float64(maxRequestsPerMinute),
		refillRate:         float64(maxRequestsPerMinute) / 60.0,
		buckets:            make(map[uint32]*bucket),
		maxConcurrentAuths: int32(maxConcurrentAuths),
		stopChan:           make(chan struct{}),
	}

	rl.wg.Add(1)
	go rl.cleanupLoop()

	return rl
}

// AllowRequest consumes one token from the bucket for uid. Returns false if
// the bucket is empty (rate limit exceeded). If rate limiting is disabled
// (maxTokens <= 0), it always returns true.
func (rl *RateLimiter) AllowRequest(uid uint32) bool {
	if rl.maxTokens <= 0 {
		return true
	}

	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[uid]
	if !ok {
		// First request from this UID — create a full bucket minus one token.
		rl.buckets[uid] = &bucket{
			tokens:     rl.maxTokens - 1,
			lastRefill: now,
		}
		return true
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * rl.refillRate
	if b.tokens > rl.maxTokens {
		b.tokens = rl.maxTokens
	}
	b.lastRefill = now

	if b.tokens < 1 {
		return false
	}

	b.tokens--
	return true
}

// AcquireAuth attempts to increment the concurrent auth counter. Returns false
// if the limit would be exceeded. If the limit is disabled (<= 0), always
// returns true.
func (rl *RateLimiter) AcquireAuth() bool {
	if rl.maxConcurrentAuths <= 0 {
		return true
	}

	for {
		current := rl.concurrentAuths.Load()
		if current >= rl.maxConcurrentAuths {
			return false
		}
		if rl.concurrentAuths.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// ReleaseAuth decrements the concurrent auth counter. Must be called after a
// successful AcquireAuth when the authentication request completes.
func (rl *RateLimiter) ReleaseAuth() {
	rl.concurrentAuths.Add(-1)
}

// Stop terminates the background cleanup goroutine and waits for it to exit.
func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
	rl.wg.Wait()
}

// cleanupLoop periodically evicts UID buckets that have been idle for more
// than 5 minutes (fully refilled and unused).
func (rl *RateLimiter) cleanupLoop() {
	defer rl.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopChan:
			return
		case <-ticker.C:
			rl.evictStale()
		}
	}
}

// evictStale removes buckets that have not been used in more than 5 minutes.
func (rl *RateLimiter) evictStale() {
	cutoff := time.Now().Add(-5 * time.Minute)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	before := len(rl.buckets)
	for uid, b := range rl.buckets {
		if b.lastRefill.Before(cutoff) {
			delete(rl.buckets, uid)
		}
	}
	after := len(rl.buckets)

	if evicted := before - after; evicted > 0 {
		log.Debug().
			Int("evicted", evicted).
			Int("remaining", after).
			Msg("Evicted stale rate-limit buckets")
	}
}
