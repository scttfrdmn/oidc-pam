package ipc

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// RateClass is which budget a request is charged against.
//
// (#160) The two exist because they are driven by different things. A client
// chooses when to send `authenticate`; the *broker* decides how often a client
// sends `check_session`, by handing it a polling interval and a device code that
// is not valid until the user has approved it. Charging both to one budget meant
// that exhausting it refused the polls of logins already in flight — the login had
// already been permitted, and was then denied for continuing.
type RateClass string

const (
	// ClassAuthenticate is the budget for starting a new authentication.
	ClassAuthenticate RateClass = "auth"

	// ClassSession is the budget for check_session, refresh_session and
	// revoke_session: requests about a session that already exists.
	ClassSession RateClass = "session"
)

const (
	// pollsPerAuthentication is how many check_session requests one device-flow
	// login makes: the C module's DEFAULT_AUTH_TIMEOUT (90 s) divided by its
	// DEFAULT_POLL_INTERVAL (5 s), rounded up, plus headroom for a client that
	// polls faster because the provider asked it to.
	//
	// The session budget is this multiple of the authenticate budget, so that every
	// login the authenticate budget admits can also finish polling. That is the
	// property whose absence is the bug: the budget let a login start and then
	// refused it partway through.
	pollsPerAuthentication = 20

	// maxTrackedAccounts bounds the bucket map. The keys are attacker-influenced
	// (a request names the account it wants to log in as), so the map needs a
	// ceiling; validateRequest already bounds each key to 32 characters of
	// [a-z0-9_-].
	//
	// When full, the least recently used bucket is evicted. That cannot be turned
	// into a lockout: to exhaust some account's budget an attacker has to keep
	// naming that account, which keeps its bucket the *most* recently used, and so
	// the last one evicted. Cycling through names to avoid eviction hands each name
	// a fresh budget — which is what per-account budgets do anyway.
	maxTrackedAccounts = 4096

	// bucketIdleTimeout is how long an unused bucket is kept. A bucket idle for
	// longer than the time it takes to refill completely carries no information.
	bucketIdleTimeout = 5 * time.Minute
)

// bucket tracks tokens for a single (class, account) pair using a token bucket.
type bucket struct {
	tokens     float64
	lastRefill time.Time
}

// RateLimiter enforces per-account request rate limits and a global concurrent
// authentication limit. It is safe for concurrent use.
//
// The limits are keyed on the account a request names, not on the peer that sent
// it. Every peer is root — verifyPeerCredentials rejects anything else — so the
// peer identifies the PAM stack, which is the same for every login on the host.
// Keying on it produced one bucket for the whole machine, which meant any one
// caller could spend every other login's budget (#160).
//
// Per-account keying bounds a single account's request rate, and stops one
// account's traffic from denying another's. It does not stop an attacker from
// spending the budget of an account they name deliberately; closing that needs a
// second key the client does not choose (source_ip, #169) and the pending-flow
// accounting in #163.
type RateLimiter struct {
	// Token bucket parameters, per class.
	maxTokens         float64 // burst size (== MaxRequestsPerMinute)
	refillRate        float64 // tokens per second
	sessionMaxTokens  float64
	sessionRefillRate float64

	mu      sync.Mutex
	buckets map[string]*bucket

	// Concurrent auth semaphore
	maxConcurrentAuths int32
	concurrentAuths    atomic.Int32

	// Cleanup goroutine lifecycle
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewRateLimiter creates a RateLimiter. If maxRequestsPerMinute or
// maxConcurrentAuths is <= 0, that particular limit is disabled (always
// allows). A background goroutine evicts idle buckets every 5 minutes.
//
// maxRequestsPerMinute is the budget for new authentications, per account.
// Session requests get pollsPerAuthentication times as many, since one
// authentication is followed by many of them.
func NewRateLimiter(maxRequestsPerMinute, maxConcurrentAuths int) *RateLimiter {
	sessionPerMinute := float64(maxRequestsPerMinute) * pollsPerAuthentication

	rl := &RateLimiter{
		maxTokens:          float64(maxRequestsPerMinute),
		refillRate:         float64(maxRequestsPerMinute) / 60.0,
		sessionMaxTokens:   sessionPerMinute,
		sessionRefillRate:  sessionPerMinute / 60.0,
		buckets:            make(map[string]*bucket),
		maxConcurrentAuths: int32(maxConcurrentAuths),
		stopChan:           make(chan struct{}),
	}

	rl.wg.Add(1)
	go rl.cleanupLoop()

	return rl
}

// Allow consumes one token from the bucket for (class, account). It returns false
// if the bucket is empty (rate limit exceeded). If rate limiting is disabled
// (maxTokens <= 0), it always returns true.
//
// An empty account is a valid key: it is the one every request that names no
// account shares, and there is no reason to exempt it.
func (rl *RateLimiter) Allow(class RateClass, account string) bool {
	maxTokens, refillRate := rl.maxTokens, rl.refillRate
	if class == ClassSession {
		maxTokens, refillRate = rl.sessionMaxTokens, rl.sessionRefillRate
	}
	if maxTokens <= 0 {
		return true
	}

	// The class is part of the key, not just of the parameters: an exhausted
	// authenticate budget must not drain the session budget of the same account.
	key := string(class) + ":" + account
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		if len(rl.buckets) >= maxTrackedAccounts {
			rl.makeRoom()
		}
		// First request for this key — create a full bucket minus one token.
		rl.buckets[key] = &bucket{
			tokens:     maxTokens - 1,
			lastRefill: now,
		}
		return true
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * refillRate
	if b.tokens > maxTokens {
		b.tokens = maxTokens
	}
	b.lastRefill = now

	if b.tokens < 1 {
		return false
	}

	b.tokens--
	return true
}

// makeRoom frees a slot in a full bucket map: idle buckets first, and failing
// that the least recently used one. Callers hold rl.mu.
func (rl *RateLimiter) makeRoom() {
	if rl.evictIdleLocked() > 0 {
		return
	}

	var oldestKey string
	var oldest time.Time
	for key, b := range rl.buckets {
		if oldestKey == "" || b.lastRefill.Before(oldest) {
			oldestKey, oldest = key, b.lastRefill
		}
	}
	if oldestKey != "" {
		delete(rl.buckets, oldestKey)
		log.Debug().
			Int("tracked", len(rl.buckets)).
			Msg("Rate-limit bucket map full; evicted the least recently used bucket")
	}
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

// cleanupLoop periodically evicts buckets that have been idle for more than
// bucketIdleTimeout (fully refilled and unused).
func (rl *RateLimiter) cleanupLoop() {
	defer rl.wg.Done()

	ticker := time.NewTicker(bucketIdleTimeout)
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

// evictStale removes buckets that have not been used in more than
// bucketIdleTimeout.
func (rl *RateLimiter) evictStale() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if evicted := rl.evictIdleLocked(); evicted > 0 {
		log.Debug().
			Int("evicted", evicted).
			Int("remaining", len(rl.buckets)).
			Msg("Evicted idle rate-limit buckets")
	}
}

// evictIdleLocked deletes every bucket idle for longer than bucketIdleTimeout and
// reports how many went. Callers hold rl.mu.
func (rl *RateLimiter) evictIdleLocked() int {
	cutoff := time.Now().Add(-bucketIdleTimeout)

	evicted := 0
	for key, b := range rl.buckets {
		if b.lastRefill.Before(cutoff) {
			delete(rl.buckets, key)
			evicted++
		}
	}
	return evicted
}
