package ipc

import (
	"sync"
	"testing"
	"time"
)

func TestAllowRequest(t *testing.T) {
	// 6 requests/minute = 1 token every 10 seconds, burst of 6
	rl := NewRateLimiter(6, 0)
	defer rl.Stop()

	uid := uint32(1000)

	// Should allow 6 requests (full burst)
	for i := 0; i < 6; i++ {
		if !rl.AllowRequest(uid) {
			t.Fatalf("request %d should have been allowed", i+1)
		}
	}

	// 7th should be denied
	if rl.AllowRequest(uid) {
		t.Fatal("request should have been denied after burst exhausted")
	}
}

func TestAllowRequestRefill(t *testing.T) {
	// 60 requests/minute = 1 token/second
	rl := NewRateLimiter(60, 0)
	defer rl.Stop()

	uid := uint32(1000)

	// Exhaust all tokens
	for i := 0; i < 60; i++ {
		rl.AllowRequest(uid)
	}
	if rl.AllowRequest(uid) {
		t.Fatal("should be denied when exhausted")
	}

	// Manually advance the bucket's lastRefill to simulate time passing.
	rl.mu.Lock()
	b := rl.buckets[uid]
	b.lastRefill = b.lastRefill.Add(-2 * time.Second)
	rl.mu.Unlock()

	// Should now have ~2 tokens refilled
	if !rl.AllowRequest(uid) {
		t.Fatal("should be allowed after refill")
	}
}

func TestAllowRequestPerUID(t *testing.T) {
	rl := NewRateLimiter(2, 0)
	defer rl.Stop()

	uid1 := uint32(1000)
	uid2 := uint32(2000)

	// Exhaust UID 1
	rl.AllowRequest(uid1)
	rl.AllowRequest(uid1)
	if rl.AllowRequest(uid1) {
		t.Fatal("uid1 should be denied")
	}

	// UID 2 should still be fine
	if !rl.AllowRequest(uid2) {
		t.Fatal("uid2 should be allowed (independent bucket)")
	}
}

func TestAllowRequestDisabled(t *testing.T) {
	rl := NewRateLimiter(0, 0)
	defer rl.Stop()

	// Should always allow when disabled
	for i := 0; i < 100; i++ {
		if !rl.AllowRequest(uint32(1000)) {
			t.Fatal("should always allow when rate limiting is disabled")
		}
	}
}

func TestConcurrentAuthLimit(t *testing.T) {
	rl := NewRateLimiter(0, 3)
	defer rl.Stop()

	// Acquire 3 (max)
	for i := 0; i < 3; i++ {
		if !rl.AcquireAuth() {
			t.Fatalf("acquire %d should have succeeded", i+1)
		}
	}

	// 4th should fail
	if rl.AcquireAuth() {
		t.Fatal("should not exceed max concurrent auths")
	}

	// Release one
	rl.ReleaseAuth()

	// Now should succeed again
	if !rl.AcquireAuth() {
		t.Fatal("should succeed after release")
	}
}

func TestConcurrentAuthDisabled(t *testing.T) {
	rl := NewRateLimiter(0, 0)
	defer rl.Stop()

	// Should always allow when disabled
	for i := 0; i < 100; i++ {
		if !rl.AcquireAuth() {
			t.Fatal("should always allow when limit is disabled")
		}
	}
}

func TestConcurrentAuthConcurrency(t *testing.T) {
	rl := NewRateLimiter(0, 5)
	defer rl.Stop()

	// Use many goroutines to test for races
	var wg sync.WaitGroup
	acquired := make(chan struct{}, 100)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.AcquireAuth() {
				acquired <- struct{}{}
				time.Sleep(10 * time.Millisecond)
				rl.ReleaseAuth()
			}
		}()
	}

	wg.Wait()
	close(acquired)

	count := 0
	for range acquired {
		count++
	}
	if count == 0 {
		t.Fatal("at least some acquires should have succeeded")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	rl := NewRateLimiter(10, 0)
	defer rl.Stop()

	// Add some entries
	rl.AllowRequest(1000)
	rl.AllowRequest(2000)
	rl.AllowRequest(3000)

	// Manually age the buckets
	rl.mu.Lock()
	staleTime := time.Now().Add(-10 * time.Minute)
	for _, b := range rl.buckets {
		b.lastRefill = staleTime
	}
	rl.mu.Unlock()

	// Run eviction directly
	rl.evictStale()

	rl.mu.Lock()
	remaining := len(rl.buckets)
	rl.mu.Unlock()

	if remaining != 0 {
		t.Fatalf("expected 0 buckets after eviction, got %d", remaining)
	}
}

func TestRateLimiterCleanupKeepsFresh(t *testing.T) {
	rl := NewRateLimiter(10, 0)
	defer rl.Stop()

	rl.AllowRequest(1000) // fresh
	rl.AllowRequest(2000) // will be aged

	// Age only UID 2000
	rl.mu.Lock()
	rl.buckets[2000].lastRefill = time.Now().Add(-10 * time.Minute)
	rl.mu.Unlock()

	rl.evictStale()

	rl.mu.Lock()
	_, has1000 := rl.buckets[1000]
	_, has2000 := rl.buckets[2000]
	rl.mu.Unlock()

	if !has1000 {
		t.Fatal("fresh bucket for UID 1000 should not be evicted")
	}
	if has2000 {
		t.Fatal("stale bucket for UID 2000 should be evicted")
	}
}
