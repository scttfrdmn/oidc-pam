package auth

import (
	"sort"
	"time"

	sshpkg "github.com/scttfrdmn/oidc-pam/pkg/ssh"
)

// Session status values reported by ListSessions.
const (
	// SessionStatusPending is a device flow the user has not completed. The
	// session exists so the poller can find it, but it grants nothing.
	SessionStatusPending = "pending"
	// SessionStatusActive is an authenticated session.
	SessionStatusActive = "active"
	// SessionStatusExpired is a session past its ExpiresAt that the cleanup
	// sweep has not removed yet. It is not usable: every lookup path rechecks
	// expiry rather than trusting the sweep.
	SessionStatusExpired = "expired"
)

// BrokerStatus is a snapshot of the broker's runtime state, as reported by
// `oidc-admin status`.
type BrokerStatus struct {
	Version         string
	StartedAt       time.Time
	Uptime          time.Duration
	ActiveSessions  int
	PendingSessions int
	Providers       []string
}

// SessionInfo describes one session for operator-facing listings. It carries no
// token material, no token ID and no group memberships: a listing answers "who
// is logged in", and the audit log is the record for everything else.
type SessionInfo struct {
	ID        string
	UserID    string
	Provider  string
	LoginType string
	CreatedAt time.Time
	ExpiresAt time.Time
	Status    string
}

// SetVersion records the broker binary's version so `oidc-admin status` can
// report it. The version is an ldflags variable in package main, which pkg/auth
// cannot see; without this the status output would have to say "unknown".
func (b *Broker) SetVersion(version string) {
	b.version = version
}

// Status returns a snapshot of the broker's runtime state.
//
// Uptime is measured from Start, not from NewBroker: it answers "how long has
// this broker been serving requests". A broker that was constructed but never
// started reports a zero StartedAt and zero uptime rather than a fabricated one.
func (b *Broker) Status() BrokerStatus {
	status := BrokerStatus{
		Version:   b.version,
		StartedAt: b.startedAt,
	}
	if status.Version == "" {
		status.Version = "unknown"
	}
	if !b.startedAt.IsZero() {
		status.Uptime = time.Since(b.startedAt)
	}

	if b.config != nil {
		status.Providers = make([]string, 0, len(b.config.OIDC.Providers))
		for _, provider := range b.config.OIDC.Providers {
			status.Providers = append(status.Providers, provider.Name)
		}
		sort.Strings(status.Providers)
	}

	b.sessionMutex.RLock()
	defer b.sessionMutex.RUnlock()
	for _, session := range b.sessions {
		if session.IsActive {
			status.ActiveSessions++
		} else {
			status.PendingSessions++
		}
	}

	return status
}

// ListSessions returns every session the broker is holding, newest first.
//
// Pending device flows are included and labelled as such. Hiding them would make
// the listing useless for the thing an operator most often needs it for —
// working out whether a login that appears to be hanging has reached the broker
// at all.
func (b *Broker) ListSessions() []SessionInfo {
	now := time.Now()

	b.sessionMutex.RLock()
	infos := make([]SessionInfo, 0, len(b.sessions))
	for _, session := range b.sessions {
		infos = append(infos, SessionInfo{
			ID:        session.ID,
			UserID:    session.UserID,
			Provider:  session.Provider,
			LoginType: session.LoginType,
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
			Status:    sessionStatus(session, now),
		})
	}
	b.sessionMutex.RUnlock()

	// Newest first, then by ID so the order is stable for equal timestamps —
	// map iteration order is random, and an unstable listing is hard to read and
	// impossible to diff between two runs.
	sort.Slice(infos, func(i, j int) bool {
		if !infos[i].CreatedAt.Equal(infos[j].CreatedAt) {
			return infos[i].CreatedAt.After(infos[j].CreatedAt)
		}
		return infos[i].ID < infos[j].ID
	})

	return infos
}

func sessionStatus(session *Session, now time.Time) string {
	switch {
	case !session.ExpiresAt.IsZero() && now.After(session.ExpiresAt):
		return SessionStatusExpired
	case session.IsActive:
		return SessionStatusActive
	default:
		return SessionStatusPending
	}
}

// ListKeys returns metadata for the SSH keys the broker manages, sorted by
// username, along with the number of key directories it could not read.
func (b *Broker) ListKeys() ([]sshpkg.KeyInfo, int, error) {
	if b.keyManager == nil {
		return nil, 0, nil
	}

	keys, unreadable, err := b.keyManager.ListKeyInfo()
	if err != nil {
		return nil, 0, err
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i].Username < keys[j].Username })
	return keys, unreadable, nil
}
