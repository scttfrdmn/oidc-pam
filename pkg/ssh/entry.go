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

// expiryTimeOption is sshd's per-key expiry option (sshd(8), AUTHORIZED_KEYS FILE
// FORMAT). sshd refuses the key after the time given.
//
// It needs OpenSSH minOpenSSHVersion or newer. An sshd that does not recognise an
// option refuses the entry carrying it, so on anything older every key the broker
// installs is rejected and the account is authenticated and then cannot log in —
// the failure #171 is about, reached by a different route.
const expiryTimeOption = "expiry-time"

// minOpenSSHVersion is the oldest sshd that understands what this package writes.
// OpenSSH 7.7 added expiry-time= for authorized_keys, and the timespec written
// below is deliberately the form 7.7 accepts.
//
// It is a constant here so pkg/ssh/docs_test.go can hold DEPLOYMENT.md and
// README.md to the same number: a version requirement only this file knows about
// is one an operator discovers from a login that does not work.
const minOpenSSHVersion = "7.7"

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

// expiryTimespecLayout is the format the broker writes: sshd's YYYYMMDDHHMMSS,
// rendered at the host zone's standard-time offset (see standardTimeOffset).
//
// Not the UTC form. Suffixing the timespec with Z to mean UTC was added in OpenSSH
// 9.1; every sshd before that parses a timespec by its length (8, 12 or 14 digits)
// and rejects the 15-character Z form outright, taking the whole entry with it. So
// writing UTC would have limited this to Debian 12/Ubuntu 24.04-era hosts and
// broken RHEL 8 and 9, Debian 11 and Ubuntu 20.04 and 22.04 — and broken them in
// the way that is hardest to see, since the file looks correct and only sshd
// disagrees.
//
// Verified rather than assumed: misc.c at tag V_9_0_P1 switches on strlen(s) over
// {8,12,14} and returns SSH_ERR_INVALID_FORMAT for anything else, while V_9_1_P1 is
// the first tag that strips a trailing "Z"/"UTC" before that switch. So the plain
// 14-digit form is the only one the supported range parses, and #226's proposed fix
// — append "Z" — would deny every login on the majority of supported platforms.
const expiryTimespecLayout = "20060102150405"

// standardTimeOffset returns the UTC offset loc keeps when daylight saving is *not*
// in effect around t. It is the offset sshd will use to read an unsuffixed timespec,
// and it is not necessarily the offset in force at t.
//
// (#226) This is what the option's value has to be rendered at, and getting it wrong
// is a revocation gap rather than cosmetic drift. sshd parses the timespec with
// parse_absolute_time() (misc.c), which does:
//
//	memset(&tm, 0, sizeof(tm));
//	strptime(buf, fmt, &tm);
//	mktime(&tm);
//
// The memset leaves tm.tm_isdst == 0, and strptime does not set it. Zero means "DST
// is not in effect" — not "work it out", which would be -1 — so mktime resolves the
// wall clock at the zone's standard offset whatever time of year it is. Measured, on
// both libcs that matter, for 2026-08-14 12:00:00 in America/New_York:
//
//	tm_isdst =  0  ->  2026-08-14 17:00 UTC   (i.e. 12:00 EST)
//	tm_isdst = -1  ->  2026-08-14 16:00 UTC   (i.e. 12:00 EDT)
//
// identical on Darwin libc and on glibc 2.41 (Debian, python:3-slim), which settles
// the question #226 left open. Rendering the expiry at the offset in force at t —
// what this used to do — therefore made sshd honour a key for an hour longer than
// the session it belonged to for the whole of the DST half of the year: the broker
// expired the session, the audit trail said the access had ended, and the key still
// authenticated. Rendering it at the standard offset makes the two agree exactly.
//
// A host in UTC, or in any zone with no DST rule, is unaffected either way: t is
// never DST there, so this returns the offset at t and the output is unchanged.
func standardTimeOffset(t time.Time, loc *time.Location) int {
	local := t.In(loc)
	if !local.IsDST() {
		_, offset := local.Zone()
		return offset
	}
	// Probe outward for the nearest instant in this zone that is not DST and take
	// that period's offset. This is deliberately the same search glibc's mktime makes
	// when the tm it is handed asks for an isdst it cannot satisfy locally, so the two
	// arrive at the same offset. A day's granularity is enough: the shortest non-DST
	// period in the tz database is about eight days (Africa/Tunis, 1943), and the
	// shortest DST period about seven.
	for days := 1; days <= 200; days++ {
		for _, direction := range []int{-1, 1} {
			if probe := local.AddDate(0, 0, direction*days); !probe.IsDST() {
				_, offset := probe.Zone()
				return offset
			}
		}
	}
	// A zone that is on DST all year round (Europe/Dublin's negative-DST encoding is
	// the closest real case). Nothing better to say than the offset at t.
	_, offset := local.Zone()
	return offset
}

// parseExpiryTimespec reads any of the forms sshd(8) documents for a timespec:
// YYYYMMDD or YYYYMMDDHHMM[SS], each optionally suffixed with Z for UTC and
// otherwise at the host zone's standard-time offset.
//
// It reads more forms than formatExpiryTimespec writes on purpose. The sweep must
// agree with sshd about when an entry stops working, and an entry it did not write
// — an operator's own expiring key, or the Z form an sshd 9.1+ host accepts — is
// still one whose expiry it should honour rather than guess at.
//
// (#226) Reading the unsuffixed form at the standard offset rather than "in local
// time" is the other half of that agreement. Parsing with time.ParseInLocation and
// time.Local resolves a summer wall clock as DST, which is precisely what sshd does
// not do — so the sweep would have removed a key up to an hour before sshd stopped
// honouring it, dropping users mid-session, and the round trip through
// formatExpiryTimespec would not have been the identity.
func parseExpiryTimespec(value string) (time.Time, bool) {
	return parseExpiryTimespecIn(value, time.Local)
}

// parseExpiryTimespecIn is parseExpiryTimespec against an explicit zone, so that the
// DST behaviour can be tested on a host in any time zone.
func parseExpiryTimespecIn(value string, loc *time.Location) (time.Time, bool) {
	isUTC := strings.HasSuffix(value, "Z") || strings.HasSuffix(value, "z")
	if isUTC {
		value = value[:len(value)-1]
	}
	for _, layout := range []string{"20060102150405", "200601021504", "20060102"} {
		// Read the digits as a wall clock first, with no zone applied, then place it.
		nominal, err := time.ParseInLocation(layout, value, time.UTC)
		if err != nil {
			continue
		}
		if isUTC {
			return nominal, true
		}
		// Within an hour or so of a DST transition the standard offset derived from
		// nominal can be the neighbouring period's, and mktime's own search has the
		// same ambiguity from the other side. An hour of disagreement in the two hours
		// a year a transition covers is not worth a second parse to chase.
		offset := standardTimeOffset(nominal, loc)
		return nominal.Add(-time.Duration(offset) * time.Second), true
	}
	return time.Time{}, false
}

// formatExpiryTimespec renders an expiry for sshd's expiry-time= option at the host
// zone's standard-time offset, because that is how sshd reads an unsuffixed timespec
// whatever the time of year (#226; see standardTimeOffset).
func formatExpiryTimespec(t time.Time) string {
	return formatExpiryTimespecIn(t, time.Local)
}

// formatExpiryTimespecIn is formatExpiryTimespec against an explicit zone, so that
// the DST behaviour can be tested on a host in any time zone.
func formatExpiryTimespecIn(t time.Time, loc *time.Location) string {
	offset := standardTimeOffset(t, loc)
	return t.In(time.FixedZone("", offset)).Format(expiryTimespecLayout)
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

// pruneBrokerComments removes every provenance comment that no longer describes
// anything. A comment claiming the broker added a key, sitting above the user's own
// keys because the key it described has been revoked, misleads whoever reads the file
// next.
//
// The comment belongs to the entry below it, so a comment survives only if the next
// entry in the file is a broker-issued one and no newer provenance comment has come
// between the two. (#227) That is finer-grained than the "is there any broker entry
// left anywhere" test this used to make, which was sufficient only while an account
// held at most one broker entry: with a live entry per concurrent session, removing one
// of several entries used to leave its comment behind claiming a date for the entry
// that happened to follow it.
func pruneBrokerComments(lines []string) []string {
	kept := make([]string, 0, len(lines))
	for i, line := range lines {
		if isBrokerComment(line) && !describesABrokerEntry(lines[i+1:]) {
			continue
		}
		kept = append(kept, line)
	}
	return kept
}

// describesABrokerEntry reports whether the lines following a provenance comment make
// it a comment about a broker-issued entry. Blank lines do not separate a comment from
// its entry; a later provenance comment does, because that one is the entry's own.
func describesABrokerEntry(rest []string) bool {
	for _, line := range rest {
		if isBrokerComment(line) {
			return false
		}
		if entry, ok := parseKeyEntry(line); ok {
			return entry.brokerIssued()
		}
	}
	return false
}
