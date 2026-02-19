package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// helpers

func newLH(t *testing.T, cfg config.LocationHistoryConfig) *LocationHistory {
	t.Helper()
	return NewLocationHistory(cfg)
}

func defaultLH(t *testing.T) *LocationHistory {
	t.Helper()
	return newLH(t, config.LocationHistoryConfig{})
}

// TestSubnetKey verifies /24 and /48 bucketing.
func TestSubnetKey(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"1.2.3.100", "1.2.3.0/24"},
		{"1.2.3.1", "1.2.3.0/24"},
		{"10.0.0.255", "10.0.0.0/24"},
		{"2001:db8::1", "2001:db8::/48"},
		{"not-an-ip", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := subnetKey(c.ip)
		if got != c.want {
			t.Errorf("subnetKey(%q) = %q, want %q", c.ip, got, c.want)
		}
	}
}

// TestLocationHistoryFirstLogin: first login → not unusual, entry recorded.
func TestLocationHistoryFirstLogin(t *testing.T) {
	lh := defaultLH(t)

	if lh.IsUnusual("alice", "1.2.3.4", "US") {
		t.Error("Expected first login to be NOT unusual")
	}
	lh.RecordLocation("alice", "1.2.3.4", "US")
	if lh.Len("alice") != 1 {
		t.Errorf("Expected 1 entry after first record, got %d", lh.Len("alice"))
	}
}

// TestLocationHistoryKnownSubnet: subsequent login from same /24 → not unusual.
func TestLocationHistoryKnownSubnet(t *testing.T) {
	lh := defaultLH(t)
	lh.RecordLocation("alice", "1.2.3.4", "US")

	// Different host in the same /24.
	if lh.IsUnusual("alice", "1.2.3.200", "US") {
		t.Error("Expected same /24 subnet to be NOT unusual")
	}
	// Different /24 entirely.
	if !lh.IsUnusual("alice", "5.6.7.8", "DE") {
		t.Error("Expected different /24 and country to be unusual")
	}
}

// TestLocationHistoryKnownCountry: same country but different /24 → not unusual.
func TestLocationHistoryKnownCountry(t *testing.T) {
	lh := defaultLH(t)
	lh.RecordLocation("alice", "1.2.3.4", "US")

	// Different IP, same country.
	if lh.IsUnusual("alice", "5.6.7.8", "US") {
		t.Error("Expected same country to be NOT unusual")
	}
}

// TestLocationHistoryUnknownLocation: no subnet/country match → unusual.
func TestLocationHistoryUnknownLocation(t *testing.T) {
	lh := defaultLH(t)
	lh.RecordLocation("alice", "1.2.3.4", "US")

	if !lh.IsUnusual("alice", "200.100.50.1", "BR") {
		t.Error("Expected unknown subnet+country to be unusual")
	}
}

// TestLocationHistoryUnknownEmptyCountry: no country available; falls back to
// subnet-only matching.
func TestLocationHistoryUnknownEmptyCountry(t *testing.T) {
	lh := defaultLH(t)
	lh.RecordLocation("alice", "1.2.3.4", "") // recorded without country

	// Same subnet — should still be recognised.
	if lh.IsUnusual("alice", "1.2.3.99", "") {
		t.Error("Expected same /24 with empty country to be NOT unusual")
	}
	// Different subnet, still no country.
	if !lh.IsUnusual("alice", "9.9.9.9", "") {
		t.Error("Expected different /24 with empty country to be unusual")
	}
}

// TestLocationHistoryMaxLocations: oldest entry is evicted when cap is hit.
func TestLocationHistoryMaxLocations(t *testing.T) {
	lh := newLH(t, config.LocationHistoryConfig{MaxLocationsPerUser: 3})

	lh.RecordLocation("alice", "1.0.0.1", "A1")
	lh.RecordLocation("alice", "2.0.0.1", "A2")
	lh.RecordLocation("alice", "3.0.0.1", "A3")
	// Cap reached; adding a 4th should evict the oldest (1.0.0.0/24).
	lh.RecordLocation("alice", "4.0.0.1", "A4")

	if n := lh.Len("alice"); n != 3 {
		t.Errorf("Expected 3 entries (capped), got %d", n)
	}
	// The evicted subnet (1.0.0.0/24) should now be considered unusual.
	if !lh.IsUnusual("alice", "1.0.0.99", "UNKNOWN") {
		t.Error("Expected evicted subnet to be unusual after cap eviction")
	}
	// The newly added subnet should still be known.
	if lh.IsUnusual("alice", "4.0.0.2", "") {
		t.Error("Expected recently added subnet to be NOT unusual")
	}
}

// TestLocationHistoryWindowExpiry: entries older than HistoryWindow are ignored.
func TestLocationHistoryWindowExpiry(t *testing.T) {
	lh := newLH(t, config.LocationHistoryConfig{HistoryWindow: time.Hour})

	// Inject a stale entry directly (bypassing time.Now() in RecordLocation).
	lh.mu.Lock()
	lh.entries["alice"] = []LocationEntry{
		{
			IP:      "1.2.3.4",
			Subnet:  "1.2.3.0/24",
			Country: "US",
			SeenAt:  time.Now().Add(-2 * time.Hour), // older than the window
		},
	}
	lh.mu.Unlock()

	// The expired entry must not prevent flagging as unusual.
	if !lh.IsUnusual("alice", "1.2.3.99", "US") {
		t.Error("Expected expired entry to be ignored, so location should be unusual")
	}

	// RecordLocation must prune the stale entry when adding a fresh one.
	lh.RecordLocation("alice", "5.5.5.5", "DE")
	if n := lh.Len("alice"); n != 1 {
		t.Errorf("Expected stale entry pruned, got %d entries", n)
	}
}

// TestLocationHistoryDeduplication: recording the same subnet twice updates
// SeenAt rather than creating a second entry.
func TestLocationHistoryDeduplication(t *testing.T) {
	lh := defaultLH(t)
	lh.RecordLocation("alice", "1.2.3.4", "US")
	lh.RecordLocation("alice", "1.2.3.100", "US") // same /24

	if n := lh.Len("alice"); n != 1 {
		t.Errorf("Expected 1 entry after deduplication, got %d", n)
	}
}

// TestLocationHistoryMultipleUsers: histories are per-user and do not interfere.
func TestLocationHistoryMultipleUsers(t *testing.T) {
	lh := defaultLH(t)
	lh.RecordLocation("alice", "1.2.3.4", "US")
	lh.RecordLocation("bob", "5.6.7.8", "DE")

	// Alice's location should not count as known for bob.
	if !lh.IsUnusual("bob", "1.2.3.4", "US") {
		t.Error("Expected alice's subnet to be unusual for bob")
	}
	// Bob's location should not count as known for alice.
	if !lh.IsUnusual("alice", "5.6.7.8", "DE") {
		t.Error("Expected bob's subnet to be unusual for alice")
	}
}

// TestLocationHistoryPersistence: save and reload round-trips correctly.
func TestLocationHistoryPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lh.json")

	cfg := config.LocationHistoryConfig{PersistPath: path}
	lh1 := newLH(t, cfg)
	lh1.RecordLocation("alice", "1.2.3.4", "US")
	lh1.RecordLocation("alice", "10.0.0.1", "US")

	// Wait for async persistence goroutine.
	waitForFile(t, path, 2*time.Second)

	// Load into a fresh instance.
	lh2 := newLH(t, cfg)
	if n := lh2.Len("alice"); n != 2 {
		t.Errorf("Expected 2 entries after reload, got %d", n)
	}
	// Known location must still be recognised.
	if lh2.IsUnusual("alice", "1.2.3.99", "US") {
		t.Error("Expected previously saved subnet to be recognised after reload")
	}
}

// TestLocationHistoryPersistenceFileNotExist: missing persist file is silently
// ignored (not an error).
func TestLocationHistoryPersistenceFileNotExist(t *testing.T) {
	lh := newLH(t, config.LocationHistoryConfig{
		PersistPath: "/tmp/does-not-exist-lh-test.json",
	})
	// Nothing persisted yet — history should be empty, not an error.
	if lh.Len("alice") != 0 {
		t.Errorf("Expected 0 entries for unknown user, got %d", lh.Len("alice"))
	}
}

// TestLocationHistoryPersistenceInvalidJSON: corrupt persist file is treated as
// an empty history (warning logged, no panic).
func TestLocationHistoryPersistenceInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lh.json")
	if err := os.WriteFile(path, []byte("not json{{"), 0600); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}
	// Should not panic; history starts empty.
	lh := newLH(t, config.LocationHistoryConfig{PersistPath: path})
	if lh.Len("alice") != 0 {
		t.Errorf("Expected 0 entries after corrupt file, got %d", lh.Len("alice"))
	}
}

// TestLocationHistoryJSONRoundTrip: manual JSON marshal/unmarshal preserves data.
func TestLocationHistoryJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lh.json")

	original := map[string][]LocationEntry{
		"alice": {
			{IP: "1.2.3.4", Subnet: "1.2.3.0/24", Country: "US", SeenAt: time.Now().Truncate(time.Second)},
		},
	}
	if err := saveLocationHistoryJSON(path, original); err != nil {
		t.Fatalf("saveLocationHistoryJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var loaded map[string][]LocationEntry
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(loaded["alice"]) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(loaded["alice"]))
	}
	if loaded["alice"][0].Country != "US" {
		t.Errorf("Expected country US, got %q", loaded["alice"][0].Country)
	}
}

// TestLocationHistoryConcurrent: concurrent RecordLocation/IsUnusual calls must
// not race (run with -race).
func TestLocationHistoryConcurrent(t *testing.T) {
	lh := defaultLH(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			lh.RecordLocation("user", "1.2.3.4", "US")
		}(i)
		go func(n int) {
			defer wg.Done()
			_ = lh.IsUnusual("user", "1.2.3.4", "US")
		}(i)
	}
	wg.Wait()
}

// TestPolicyEngineIsUnusualLocationIntegration: PolicyEngine.isUnusualLocation
// uses the LocationHistory correctly.
func TestPolicyEngineIsUnusualLocationIntegration(t *testing.T) {
	pe := &PolicyEngine{
		locationHistory: NewLocationHistory(config.LocationHistoryConfig{}),
	}

	// First check — no history — not unusual.
	if pe.isUnusualLocation("alice", "1.2.3.4") {
		t.Error("Expected no history to return not-unusual")
	}

	// Record a location then check the same subnet.
	pe.locationHistory.RecordLocation("alice", "1.2.3.4", "")
	if pe.isUnusualLocation("alice", "1.2.3.99") {
		t.Error("Expected same /24 subnet to be not unusual")
	}

	// Different subnet with no country resolution (no geoipDB) → unusual.
	if !pe.isUnusualLocation("alice", "9.9.9.9") {
		t.Error("Expected unknown subnet/country to be unusual")
	}
}

// waitForFile polls until path exists or the deadline is exceeded.
func waitForFile(t *testing.T, path string, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q to be created", path)
}
