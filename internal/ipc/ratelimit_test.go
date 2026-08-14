package ipc

import (
	"fmt"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The keys these tests use are account names, because that is what the limiter is
// keyed on in production. The previous version of this file drove the limiter with
// synthetic uids 1000/2000/3000 — a state that could not occur, since
// verifyPeerCredentials rejects every peer whose uid is not 0. The bucket map had
// exactly one entry on a real host, and the tests could not see it (#160).

// TestOneAccountCannotSpendAnothersBudget is the first acceptance criterion of
// #160: the attack was an unauthenticated client opening SSH connections to any
// syntactically valid username until the single host-wide bucket was empty, at
// which point every login on the machine was refused.
func TestOneAccountCannotSpendAnothersBudget(t *testing.T) {
	rl := NewRateLimiter(4, 0)
	defer rl.Stop()

	// The attacker names one account, or a hundred, and empties what they can.
	for i := 0; i < 400; i++ {
		rl.Allow(ClassAuthenticate, fmt.Sprintf("victim%d", i%100))
	}
	if rl.Allow(ClassAuthenticate, "victim0") {
		t.Fatal("victim0's own budget should be spent after 4 requests naming it")
	}

	// The user who was not named still has their full burst.
	for i := 0; i < 4; i++ {
		if !rl.Allow(ClassAuthenticate, "alice") {
			t.Fatalf("alice's login %d was refused because of traffic for other accounts", i+1)
		}
	}
}

// TestPollsSurviveAnExhaustedAuthenticateBudget is the second acceptance criterion.
// A login that has already been permitted must be able to finish: the broker itself
// chose the polling interval, so refusing the polls denies a login it just started.
func TestPollsSurviveAnExhaustedAuthenticateBudget(t *testing.T) {
	rl := NewRateLimiter(2, 0)
	defer rl.Stop()

	if !rl.Allow(ClassAuthenticate, "alice") {
		t.Fatal("first authenticate refused")
	}
	// Empty alice's authenticate budget.
	for rl.Allow(ClassAuthenticate, "alice") {
	}

	// The device flow started above still has to complete. One login is
	// pollsPerAuthentication polls; the budget has to cover at least that.
	for i := 0; i < pollsPerAuthentication; i++ {
		if !rl.Allow(ClassSession, "alice") {
			t.Fatalf("check_session %d/%d refused while the login was in flight", i+1, pollsPerAuthentication)
		}
	}
}

// TestSessionBudgetIsSeparateFromAuthenticate: spending one must not spend the
// other, in either direction. The class is part of the bucket key for this reason.
func TestSessionBudgetIsSeparateFromAuthenticate(t *testing.T) {
	rl := NewRateLimiter(3, 0)
	defer rl.Stop()

	for rl.Allow(ClassSession, "alice") {
	}
	for i := 0; i < 3; i++ {
		if !rl.Allow(ClassAuthenticate, "alice") {
			t.Fatalf("authenticate %d refused after the session budget was spent", i+1)
		}
	}
}

func TestAllowBurstThenDeny(t *testing.T) {
	// 6 requests/minute = 1 token every 10 seconds, burst of 6
	rl := NewRateLimiter(6, 0)
	defer rl.Stop()

	for i := 0; i < 6; i++ {
		if !rl.Allow(ClassAuthenticate, "alice") {
			t.Fatalf("request %d should have been allowed", i+1)
		}
	}

	if rl.Allow(ClassAuthenticate, "alice") {
		t.Fatal("request should have been denied after burst exhausted")
	}
}

func TestAllowRefill(t *testing.T) {
	// 60 requests/minute = 1 token/second
	rl := NewRateLimiter(60, 0)
	defer rl.Stop()

	for i := 0; i < 60; i++ {
		rl.Allow(ClassAuthenticate, "alice")
	}
	if rl.Allow(ClassAuthenticate, "alice") {
		t.Fatal("should be denied when exhausted")
	}

	// Manually advance the bucket's lastRefill to simulate time passing.
	rl.mu.Lock()
	b := rl.buckets[string(ClassAuthenticate)+":alice"]
	b.lastRefill = b.lastRefill.Add(-2 * time.Second)
	rl.mu.Unlock()

	// Should now have ~2 tokens refilled
	if !rl.Allow(ClassAuthenticate, "alice") {
		t.Fatal("should be allowed after refill")
	}
}

func TestAllowDisabled(t *testing.T) {
	rl := NewRateLimiter(0, 0)
	defer rl.Stop()

	// Should always allow when disabled, in both classes.
	for i := 0; i < 100; i++ {
		if !rl.Allow(ClassAuthenticate, "alice") || !rl.Allow(ClassSession, "alice") {
			t.Fatal("should always allow when rate limiting is disabled")
		}
	}
}

// TestBucketMapIsBounded: the keys are account names taken from requests, so an
// attacker naming a new account every time must not grow the map without limit.
func TestBucketMapIsBounded(t *testing.T) {
	rl := NewRateLimiter(10, 0)
	defer rl.Stop()

	for i := 0; i < maxTrackedAccounts+500; i++ {
		rl.Allow(ClassAuthenticate, fmt.Sprintf("u%d", i))
	}

	rl.mu.Lock()
	tracked := len(rl.buckets)
	rl.mu.Unlock()

	if tracked > maxTrackedAccounts {
		t.Fatalf("bucket map grew to %d entries, above the %d cap", tracked, maxTrackedAccounts)
	}
}

// TestEvictionKeepsTheAccountUnderAttack: filling the map must not be a way to
// clear the bucket of an account whose budget is being spent, since that would hand
// the attacker an unlimited budget against a chosen victim. The bucket being drained
// is the most recently used one, so it is the last to go.
func TestEvictionKeepsTheAccountUnderAttack(t *testing.T) {
	rl := NewRateLimiter(4, 0)
	defer rl.Stop()

	// Spend victim's budget, then flood with distinct names, touching victim as an
	// attacker would keep doing.
	for i := 0; i < maxTrackedAccounts*2; i++ {
		rl.Allow(ClassAuthenticate, fmt.Sprintf("filler%d", i))
		rl.Allow(ClassAuthenticate, "victim")
	}

	if rl.Allow(ClassAuthenticate, "victim") {
		t.Fatal("victim's bucket was evicted by the flood, refilling the attacker's budget")
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

// A concurrency cap larger than an int32 must still be a cap. `int32(n)` wrapped
// it to a negative number, and AcquireAuth reads <= 0 as "limit disabled", so the
// largest values an operator could write in the config were the ones that removed
// the limit entirely. math.MaxInt64 is not a plausible setting; a fat-fingered extra
// digit on a five-digit one is, and both take the same path (#189).
func TestAnOversizedConcurrencyCapIsStillACap(t *testing.T) {
	for _, configured := range []int{math.MaxInt32 + 1, math.MaxInt64} {
		rl := NewRateLimiter(0, configured)
		if rl.maxConcurrentAuths <= 0 {
			t.Errorf("max_concurrent_auths=%d became %d, which AcquireAuth treats as no limit at all",
				configured, rl.maxConcurrentAuths)
		}
		if !rl.AcquireAuth() {
			t.Errorf("max_concurrent_auths=%d refused the first authentication", configured)
		}
		rl.ReleaseAuth()
		rl.Stop()
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

	rl.Allow(ClassAuthenticate, "alice")
	rl.Allow(ClassAuthenticate, "bob")
	rl.Allow(ClassSession, "alice")

	// Manually age the buckets
	rl.mu.Lock()
	staleTime := time.Now().Add(-2 * bucketIdleTimeout)
	for _, b := range rl.buckets {
		b.lastRefill = staleTime
	}
	rl.mu.Unlock()

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

	rl.Allow(ClassAuthenticate, "alice") // fresh
	rl.Allow(ClassAuthenticate, "bob")   // will be aged

	rl.mu.Lock()
	rl.buckets[string(ClassAuthenticate)+":bob"].lastRefill = time.Now().Add(-2 * bucketIdleTimeout)
	rl.mu.Unlock()

	rl.evictStale()

	rl.mu.Lock()
	_, hasAlice := rl.buckets[string(ClassAuthenticate)+":alice"]
	_, hasBob := rl.buckets[string(ClassAuthenticate)+":bob"]
	rl.mu.Unlock()

	if !hasAlice {
		t.Fatal("fresh bucket for alice should not be evicted")
	}
	if hasBob {
		t.Fatal("idle bucket for bob should be evicted")
	}
}

// TestRateClassFor pins which request types are charged, and to which budget.
func TestRateClassFor(t *testing.T) {
	tests := []struct {
		requestType string
		wantClass   RateClass
		wantLimited bool
	}{
		{"authenticate", ClassAuthenticate, true},
		{"check_session", ClassSession, true},
		{"refresh_session", ClassSession, true},
		{"revoke_session", ClassSession, true},
		{"status", "", false},
		{"sessions_list", "", false},
		{"keys_list", "", false},
		{"nonsense", "", false},
	}
	for _, tc := range tests {
		class, limited := rateClassFor(tc.requestType)
		if class != tc.wantClass || limited != tc.wantLimited {
			t.Errorf("rateClassFor(%q) = (%q, %v), want (%q, %v)",
				tc.requestType, class, limited, tc.wantClass, tc.wantLimited)
		}
	}
}

func BenchmarkAllow(b *testing.B) {
	rl := NewRateLimiter(10000, 0)
	defer rl.Stop()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			rl.Allow(ClassAuthenticate, fmt.Sprintf("user%d", i%100))
			i++
		}
	})
}

func BenchmarkAcquireReleaseAuth(b *testing.B) {
	rl := NewRateLimiter(0, 10000)
	defer rl.Stop()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if rl.AcquireAuth() {
				rl.ReleaseAuth()
			}
		}
	})
}

// TestHandleRequestChargesTheAccountNamedInTheRequest checks the wiring: the
// limiter is consulted with the account from the request, and refusal happens
// before the request reaches the broker.
//
// Only the refusal path is exercised here. The path where the limiter allows the
// request needs a working broker — auth.NewBroker reaches the provider's discovery
// endpoint, which this test cannot do — so "bob is unaffected by alice's traffic"
// and "alice's polls are unaffected" are asserted against the limiter above.
func TestHandleRequestChargesTheAccountNamedInTheRequest(t *testing.T) {
	server, err := NewServer(filepath.Join(t.TempDir(), "test.sock"), nil, 0660, "", false, 2, 0)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer server.rateLimiter.Stop()

	// Spend alice's authenticate budget, as two earlier logins would.
	for server.rateLimiter.Allow(ClassAuthenticate, "alice") {
	}

	response := authResponse(t, server.handleRequest(&Request{Type: "authenticate", UserID: "alice"}))
	if response.Success {
		t.Error("a request over the account's budget was allowed")
	}
	if response.ErrorCode != "RATE_LIMIT_EXCEEDED" {
		t.Errorf("ErrorCode = %q, want RATE_LIMIT_EXCEEDED", response.ErrorCode)
	}

	// bob's budget was not spent by alice's traffic — the point of the fix. (Had it
	// been shared, the loop above would have emptied it too.)
	if !server.rateLimiter.Allow(ClassAuthenticate, "bob") {
		t.Error("bob's login was refused because of requests naming alice")
	}

	// Nor was alice's session budget: the polls of the login she just started have
	// to be able to complete.
	if !server.rateLimiter.Allow(ClassSession, "alice") {
		t.Error("alice's check_session was refused after her authenticate budget was spent")
	}
}
