package ipc

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/internal/adminapi"
)

// Administrative request handlers, backing `oidc-admin status`, `sessions` and
// `keys`. oidc-admin has sent these three request types since it was written,
// but the broker implemented none of them: every one fell through
// handleRequest's default case to INVALID_REQUEST_TYPE, which the client
// decoded into an empty result and printed as a running broker with no version,
// no sessions and no keys.
//
// They read broker state and take no parameters. Access control is the same as
// for every other request on this socket: the peer must be uid 0 (see
// verifyPeerCredentials), so these are root-only and `oidc-admin` must be run
// with sudo.

// handleStatus answers a `status` request.
func (s *Server) handleStatus() *adminapi.StatusResponse {
	status := s.broker.Status()

	return &adminapi.StatusResponse{
		Status:          "running",
		Version:         status.Version,
		Uptime:          formatUptime(status.Uptime),
		UptimeSeconds:   status.Uptime.Seconds(),
		StartedAt:       status.StartedAt,
		ActiveSessions:  status.ActiveSessions,
		PendingSessions: status.PendingSessions,
		Providers:       status.Providers,
		Timestamp:       time.Now(),
	}
}

// handleSessionsList answers a `sessions_list` request.
func (s *Server) handleSessionsList() *adminapi.SessionListResponse {
	sessions := s.broker.ListSessions()

	out := make([]adminapi.Session, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, adminapi.Session{
			ID:        session.ID,
			UserID:    session.UserID,
			Provider:  session.Provider,
			LoginType: session.LoginType,
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
			Status:    session.Status,
		})
	}

	return &adminapi.SessionListResponse{
		Sessions: out,
		Total:    len(out),
	}
}

// handleKeysList answers a `keys_list` request.
func (s *Server) handleKeysList() *adminapi.KeyListResponse {
	keys, unreadable, err := s.broker.ListKeys()
	if err != nil {
		log.Error().Err(err).Msg("Failed to list managed SSH keys")
		return &adminapi.KeyListResponse{
			Error: adminapi.Error{
				ErrorCode:    "KEY_LIST_FAILED",
				ErrorMessage: clientErrorMessage("KEY_LIST_FAILED"),
			},
		}
	}

	out := make([]adminapi.SSHKeyInfo, 0, len(keys))
	for _, key := range keys {
		status := "active"
		if key.Expired {
			status = "expired"
		}
		out = append(out, adminapi.SSHKeyInfo{
			Username:  key.Username,
			SessionID: key.KeyID,
			KeyType:   key.KeyType,
			KeySize:   key.KeySize,
			Status:    status,
			CreatedAt: key.CreatedAt,
			ExpiresAt: key.ExpiresAt,
		})
	}

	return &adminapi.KeyListResponse{
		Keys:       out,
		Total:      len(out),
		Unreadable: unreadable,
	}
}

// formatUptime renders a duration for an operator: whole units, largest first,
// dropping the ones that are zero at the front. time.Duration's own String would
// print "2h0m0.000481723s".
func formatUptime(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}

	d = d.Round(time.Second)
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	minutes := int(d / time.Minute)
	seconds := int((d - time.Duration(minutes)*time.Minute) / time.Second)

	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	case minutes > 0:
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}
