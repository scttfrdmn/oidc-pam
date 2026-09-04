package auth

import (
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// LocationEntry records a single successful login location for a user.
type LocationEntry struct {
	IP      string    `json:"ip"`
	Subnet  string    `json:"subnet"`  // /24 (IPv4) or /48 (IPv6) network string
	Country string    `json:"country"` // ISO 3166-1 alpha-2, may be empty
	SeenAt  time.Time `json:"seen_at"`
}

// LocationHistory is a thread-safe, per-user store of login locations used by
// the policy engine to detect unusual-location risk signals.
type LocationHistory struct {
	cfg       config.LocationHistoryConfig
	mu        sync.RWMutex
	entries   map[string][]LocationEntry // userID → recorded locations
	persistMu sync.Mutex                 // serializes concurrent disk writes
	wg        sync.WaitGroup             // tracks in-flight persistAsync goroutines
}

// NewLocationHistory creates a LocationHistory using cfg.  If cfg.PersistPath
// is non-empty it attempts to load previously saved data from that file.
func NewLocationHistory(cfg config.LocationHistoryConfig) *LocationHistory {
	lh := &LocationHistory{
		cfg:     cfg,
		entries: make(map[string][]LocationEntry),
	}
	if cfg.PersistPath != "" {
		if err := lh.load(cfg.PersistPath); err != nil {
			log.Warn().Err(err).Str("path", cfg.PersistPath).
				Msg("Could not load location history; starting with empty history")
		}
	}
	return lh
}

// subnetKey returns a canonical /24 (IPv4) or /48 (IPv6) network string for
// ipStr so that hosts in the same ISP block are treated as the same location.
// Returns "" if ipStr cannot be parsed.
func subnetKey(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	var cidr string
	if ip.To4() != nil {
		cidr = ip.String() + "/24"
	} else {
		cidr = ip.String() + "/48"
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	return network.String()
}

// IsUnusual reports whether (userID, ip, country) is unusual relative to the
// user's recorded history.  A location is "known" when a non-expired entry
// matches either the /24 subnet or the country code.  Returns false (not
// unusual) when the user has no recorded history at all.
func (lh *LocationHistory) IsUnusual(userID, ip, country string) bool {
	// Hold RLock for the entire read: releasing it before ranging over the slice
	// would leave the backing array exposed to concurrent writes in RecordLocation.
	lh.mu.RLock()
	defer lh.mu.RUnlock()

	entries := lh.entries[userID]
	if len(entries) == 0 {
		return false // first login — not unusual by definition
	}

	subnet := subnetKey(ip)
	cutoff := time.Now().Add(-lh.historyWindow())

	for _, e := range entries {
		if e.SeenAt.Before(cutoff) {
			continue // expired entry, skip
		}
		if subnet != "" && subnet == e.Subnet {
			return false // same /24 or /48 block — known location
		}
		if country != "" && country == e.Country {
			return false // same country — known location
		}
	}
	return true
}

// RecordLocation records a successful login from ip/country for userID.
//
// Behaviour:
//   - Expired entries (older than HistoryWindow) are pruned first.
//   - If an existing entry already matches the same subnet, only SeenAt and
//     Country are updated (deduplication).
//   - When the per-user cap (MaxLocationsPerUser) is reached, the oldest entry
//     is evicted to make room.
//
// A login with no usable location is not recorded at all. (#169) An entry with an
// empty Subnet and an empty Country can never match anything IsUnusual is asked
// about, but it does end the "no history yet" exemption — so recording one made
// every subsequent login for that user score as an unusual location for as long
// as the entry lived.
//
// If PersistPath is configured the updated history is saved asynchronously.
func (lh *LocationHistory) RecordLocation(userID, ip, country string) {
	subnet := subnetKey(ip)
	if subnet == "" && country == "" {
		return
	}
	now := time.Now()
	cutoff := now.Add(-lh.historyWindow())
	maxLocs := lh.cfg.MaxLocationsPerUser
	if maxLocs <= 0 {
		maxLocs = 10
	}

	lh.mu.Lock()
	defer lh.mu.Unlock()

	// Prune stale entries in-place.
	existing := lh.entries[userID]
	fresh := existing[:0]
	for _, e := range existing {
		if !e.SeenAt.Before(cutoff) {
			fresh = append(fresh, e)
		}
	}

	// Refresh an existing subnet entry rather than creating a duplicate.
	for i, e := range fresh {
		if subnet != "" && e.Subnet == subnet {
			fresh[i].SeenAt = now
			fresh[i].Country = country
			lh.entries[userID] = fresh
			lh.persistAsync()
			return
		}
	}

	// Enforce per-user cap: evict the oldest entry.
	if len(fresh) >= maxLocs {
		oldest := 0
		for i, e := range fresh {
			if e.SeenAt.Before(fresh[oldest].SeenAt) {
				oldest = i
			}
		}
		fresh = append(fresh[:oldest], fresh[oldest+1:]...)
	}

	fresh = append(fresh, LocationEntry{
		IP:      ip,
		Subnet:  subnet,
		Country: country,
		SeenAt:  now,
	})
	lh.entries[userID] = fresh
	lh.persistAsync()
}

// Len returns the number of location entries stored for userID.
func (lh *LocationHistory) Len(userID string) int {
	lh.mu.RLock()
	defer lh.mu.RUnlock()
	return len(lh.entries[userID])
}

// historyWindow returns the configured window, falling back to 90 days.
func (lh *LocationHistory) historyWindow() time.Duration {
	if lh.cfg.HistoryWindow > 0 {
		return lh.cfg.HistoryWindow
	}
	return 90 * 24 * time.Hour
}

// persistAsync saves the current history to disk in a background goroutine so
// RecordLocation never blocks on I/O.  Must be called while lh.mu is held.
func (lh *LocationHistory) persistAsync() {
	if lh.cfg.PersistPath == "" {
		return
	}
	path := lh.cfg.PersistPath
	lh.wg.Add(1)
	go func() {
		defer lh.wg.Done()
		// Serialize concurrent writes so two rapid RecordLocation calls don't
		// race on the same .tmp file.  Re-capture the snapshot at write time
		// (under RLock) rather than at launch time: whichever goroutine runs
		// last will always write the most current state, preventing a
		// stale goroutine from overwriting a newer one.
		lh.persistMu.Lock()
		defer lh.persistMu.Unlock()
		lh.mu.RLock()
		snapshot := make(map[string][]LocationEntry, len(lh.entries))
		for k, v := range lh.entries {
			cp := make([]LocationEntry, len(v))
			copy(cp, v)
			snapshot[k] = cp
		}
		lh.mu.RUnlock()
		if err := saveLocationHistoryJSON(path, snapshot); err != nil {
			log.Warn().Err(err).Str("path", path).Msg("Failed to persist location history")
		}
	}()
}

// Close waits for any in-flight asynchronous persistence goroutines to finish.
// Call this in tests (via t.Cleanup) or on graceful shutdown to avoid goroutine
// leaks and races against the temp-dir cleanup.
func (lh *LocationHistory) Close() {
	lh.wg.Wait()
}

func (lh *LocationHistory) load(path string) error {
	// gosec G304, accepted: path is cfg.PersistPath, from the broker's root-owned
	// configuration, and the only caller is NewLocationHistory at startup. No
	// authenticating user supplies any part of it.
	data, err := os.ReadFile(path) // #nosec G304 -- PersistPath from the trusted root-owned config
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing saved yet — not an error
		}
		return err
	}
	return json.Unmarshal(data, &lh.entries)
}

// saveLocationHistoryJSON writes v to path atomically via a temp file + rename.
func saveLocationHistoryJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
