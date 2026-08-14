package ssh

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// This file understands one authorized_keys line.
//
// (#171) Every function here exists because the entries the broker installs now
// carry a per-key option — `expiry-time="..."`, so that sshd itself stops
// honouring a key once it is stale rather than trusting the broker to still be
// alive and still remember the session. An options prefix breaks every way this
// package used to read a line: removal compared whole lines and would no longer
// match the key it had just written, and the expiry sweep read the comment out of
// `strings.Fields(line)[2]`, which is the key data once anything precedes the key
// type. Both of those failures are silent and both leave a working credential
// behind, so the parsing is in one place with its own tests.

// oidcMarker is what makes an entry the broker's. KeyManager.GenerateKey stamps
// every key it issues with a "<username>@oidc-pam-<unix>" comment, and that
// marker is the only thing distinguishing a key the broker is responsible for
// from a key the user put there themselves and which is none of the broker's
// business.
const oidcMarker = "@oidc-pam-"

// brokerCommentPrefix is the provenance comment the broker writes above the entry
// it installs. It is recognised so that the next write can drop the previous one
// instead of leaving a comment line per login behind.
const brokerCommentPrefix = "# Added by OIDC PAM on"

// expiryTimeOption is sshd's per-key expiry option (OpenSSH 8.2+, sshd(8)
// AUTHORIZED_KEYS FILE FORMAT). sshd refuses the key after the time given.
const expiryTimeOption = "expiry-time"

// keyEntry is one authorized_keys entry split into the parts that matter:
//
//	[options] <keyType> <blob> [comment]
type keyEntry struct {
	options string
	keyType string
	blob    string
	comment string
}

// parseKeyEntry splits an authorized_keys line. It reports false for a line that
// is blank, a comment, or otherwise not an entry — such a line is never matched,
// never expired and never rewritten, only carried through untouched.
//
// It deliberately does not verify the key: the caller is deciding which lines to
// keep, and a line whose base64 this package cannot decode still authorizes
// whoever holds the private half as far as sshd is concerned.
func parseKeyEntry(line string) (keyEntry, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return keyEntry{}, false
	}

	fields := splitOutsideQuotes(trimmed)
	entry := keyEntry{}
	if len(fields) > 0 && !looksLikeKeyType(fields[0]) {
		entry.options = fields[0]
		fields = fields[1:]
	}
	if len(fields) < 2 {
		return keyEntry{}, false
	}
	entry.keyType = fields[0]
	entry.blob = fields[1]
	if len(fields) > 2 {
		entry.comment = strings.Join(fields[2:], " ")
	}
	return entry, true
}

// splitOutsideQuotes splits on whitespace that is not inside a double-quoted
// string. Option values are quoted and may contain spaces (sshd(8): "no spaces
// are permitted, except within double quotes"), so a naive Fields() would tear
// `from="10.0.0.1, 10.0.0.2"` into pieces and mistake the second half for the key
// type.
func splitOutsideQuotes(s string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false
	escaped := false

	flush := func() {
		if current.Len() > 0 {
			fields = append(fields, current.String())
			current.Reset()
		}
	}

	for _, r := range s {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\' && inQuotes:
			current.WriteRune(r)
			escaped = true
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuotes:
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return fields
}

// looksLikeKeyType reports whether a field is an SSH public key algorithm name
// rather than an options list. Every algorithm name OpenSSH accepts in
// authorized_keys begins with one of these prefixes; an options list begins with
// an option name, none of which do.
func looksLikeKeyType(field string) bool {
	for _, prefix := range []string{"ssh-", "ecdsa-", "sk-ecdsa-", "sk-ssh-", "rsa-sha2-", "webauthn-"} {
		if strings.HasPrefix(field, prefix) {
			return true
		}
	}
	return false
}

// authorizesSameKeyAs reports whether two entries authorize the same key
// material, whatever options or comment they carry.
//
// This is "is this credential usable?", which is the question a revocation has to
// answer honestly. It is deliberately weaker than sameEntry.
func (e keyEntry) authorizesSameKeyAs(other keyEntry) bool {
	return e.keyType == other.keyType && e.blob == other.blob
}

// isSameEntryAs reports whether two entries are the same authorized_keys entry:
// same key, same comment, options ignored.
//
// Removal matches on this rather than on the whole line because the broker holds
// the bare key in its store and writes the entry with an `expiry-time=` option in
// front of it — comparing whole lines would never match again. It is deliberately
// stronger than authorizesSameKeyAs: a line that carries the same key with a
// different comment is not the entry the broker wrote, and quietly rewriting it
// would be the broker editing something that is not its own.
func (e keyEntry) isSameEntryAs(other keyEntry) bool {
	return e.authorizesSameKeyAs(other) && e.comment == other.comment
}

// brokerIssued reports whether this entry is one the broker installed.
func (e keyEntry) brokerIssued() bool {
	return strings.Contains(e.comment, oidcMarker)
}

// issuedAt reads the issue time out of the "<username>@oidc-pam-<unix>" comment.
// A comment in any other shape yields false, and every caller treats that as "do
// not touch this entry" — cleanup fails safe, never early.
func (e keyEntry) issuedAt() (time.Time, bool) {
	fields := strings.Fields(e.comment)
	if len(fields) == 0 {
		return time.Time{}, false
	}
	_, stamp, found := strings.Cut(fields[0], oidcMarker)
	if !found {
		return time.Time{}, false
	}
	unix, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(unix, 0), true
}

// expiryTime reads the entry's expiry-time= option, which is the expiry sshd
// itself enforces. Absent or unparseable yields false, and the caller falls back
// to the issue time in the comment.
func (e keyEntry) expiryTime() (time.Time, bool) {
	if e.options == "" {
		return time.Time{}, false
	}
	for _, option := range splitOptions(e.options) {
		name, value, found := strings.Cut(option, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), expiryTimeOption) {
			continue
		}
		if parsed, ok := parseExpiryTimespec(strings.Trim(strings.TrimSpace(value), `"`)); ok {
			return parsed, true
		}
	}
	return time.Time{}, false
}

// splitOptions splits an options list on the commas that separate options,
// ignoring commas inside a quoted value.
func splitOptions(options string) []string {
	var out []string
	var current strings.Builder
	inQuotes := false
	escaped := false
	for _, r := range options {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\' && inQuotes:
			escaped = true
			current.WriteRune(r)
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ',' && !inQuotes:
			out = append(out, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	out = append(out, current.String())
	return out
}

// expiryTimespecLayout is the format the broker writes: sshd's YYYYMMDDHHMMSS
// with the Z suffix that makes it UTC, so the entry means the same thing whatever
// time zone the host is set to.
const expiryTimespecLayout = "20060102150405Z"

// parseExpiryTimespec reads any of the forms sshd(8) documents for a timespec:
// YYYYMMDD or YYYYMMDDHHMM[SS], each optionally suffixed with Z for UTC and
// otherwise in the host's own time zone.
func parseExpiryTimespec(value string) (time.Time, bool) {
	loc := time.Local
	if strings.HasSuffix(value, "Z") || strings.HasSuffix(value, "z") {
		value = value[:len(value)-1]
		loc = time.UTC
	}
	for _, layout := range []string{"20060102150405", "200601021504", "20060102"} {
		if parsed, err := time.ParseInLocation(layout, value, loc); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

// formatExpiryTimespec renders an expiry for sshd's expiry-time= option.
func formatExpiryTimespec(t time.Time) string {
	return t.UTC().Format(expiryTimespecLayout)
}

// brokerEntryLine renders the authorized_keys line the broker installs: the key
// as generated, preceded by the expiry sshd will enforce on it.
//
// The expiry is on the line, and not only in the broker's memory and in the key
// comment, because everything else that was supposed to remove a stale key
// depended on this broker still running: sessions live in memory, so a restart
// orphaned every key it had ever issued, and the sweep that was meant to catch
// those only ran for users who happened to have a session expire afterwards
// (#171). sshd reads this option on every authentication, whether the broker is
// running or not.
func brokerEntryLine(publicKey []byte, expiresAt time.Time) string {
	return fmt.Sprintf("%s=%q %s", expiryTimeOption, formatExpiryTimespec(expiresAt),
		strings.TrimSpace(string(publicKey)))
}

// isBrokerComment reports whether a line is the provenance comment the broker
// writes above its entry.
func isBrokerComment(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), brokerCommentPrefix)
}

// dropStrandedBrokerComments removes the broker's provenance comments from a set
// of lines that no longer contains any broker-issued entry. A comment claiming
// the broker added a key, sitting above the user's own keys because the key it
// described has been revoked, misleads whoever reads the file next.
func dropStrandedBrokerComments(lines []string) []string {
	for _, line := range lines {
		if entry, ok := parseKeyEntry(line); ok && entry.brokerIssued() {
			return lines
		}
	}
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if isBrokerComment(line) {
			continue
		}
		kept = append(kept, line)
	}
	return kept
}
