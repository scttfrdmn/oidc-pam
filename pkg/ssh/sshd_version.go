package ssh

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// This file answers one question, and the whole design of the key's lifetime rests
// on the answer: does the sshd on this host understand the `expiry-time=` option
// that brokerEntryLine puts in front of every key the broker installs?
//
// (#199) Until now nothing asked. The option was written unconditionally, and an
// sshd that does not recognise an authorized_keys option does not ignore the option
// — it refuses the entry carrying it. So on a host running anything older than
// minOpenSSHVersion (Amazon Linux 2 and RHEL/CentOS 7 both ship 7.4p1) the broker
// authenticated the user, wrote a file that looks exactly right, reported success,
// and every subsequent SSH authentication answered `Permission denied (publickey)`
// with nothing anywhere naming the cause. That is the same "authenticated, and then
// cannot log in" failure #171 existed to end, reached by a different route, and it
// is invisible from the broker's side: the write succeeded, so there is no error to
// report and no audit event to raise.
//
// The decision taken here is to detect and refuse, at the point where the key would
// be installed, rather than to detect and silently drop the option. Dropping it
// would put the key's expiry back inside the broker's memory, which is the exact
// weakness #171 was filed about — a credential that outlives the process that was
// supposed to revoke it — so the fallback that keeps logins working is the one that
// issues keys nobody expires. Refusing costs an operator on an unsupported platform
// the use of the tool, which is what the documented requirement already said they
// had, and it costs it with a message that says what to do instead of a login that
// does not work.
//
// The refusal is at installation and not at startup only because the broker's
// startup lives in cmd/broker; installation is in any case the moment the broker is
// about to issue a credential it knows will not work, which is the moment to stop.

// sshdVersion is an OpenSSH release reduced to what decides this: the major and
// minor numbers. The portable suffix (`p1`), the distribution's own addendum
// (`Ubuntu-3ubuntu13.5`) and the OpenSSL version alongside it say nothing about
// which authorized_keys options the daemon parses.
type sshdVersion struct {
	major int
	minor int
}

func (v sshdVersion) String() string { return fmt.Sprintf("%d.%d", v.major, v.minor) }

// atLeast reports whether v is other or newer.
func (v sshdVersion) atLeast(other sshdVersion) bool {
	if v.major != other.major {
		return v.major > other.major
	}
	return v.minor >= other.minor
}

// minSSHDVersion is minOpenSSHVersion as numbers to compare against. The two are
// held to each other by TestMinSSHDVersionIsTheDocumentedRequirement rather than
// derived at init, so that the one number an operator reads in DEPLOYMENT.md, the
// one docs_test.go enforces and the one this file refuses on cannot drift apart
// without a test saying so.
var minSSHDVersion = sshdVersion{major: 7, minor: 7}

// sshdSearchPaths are the binaries the probe will run, in order, to ask the local
// sshd its version.
//
// Absolute paths and a fixed list, deliberately, for the same reason getentPath is
// one (see lookupViaGetent): this process is root, and resolving `sshd` through PATH
// would let whatever put a directory on the broker's PATH choose which program root
// executes. A host whose sshd is somewhere else is reported as undetermined rather
// than searched for.
//
// A variable so that tests can point it at a script instead of the host's real sshd.
var sshdSearchPaths = []string{
	"/usr/sbin/sshd",
	"/usr/local/sbin/sshd",
	"/usr/local/openssh/sbin/sshd",
	"/sbin/sshd",
	"/usr/bin/sshd",
}

// sshdProbeTimeout bounds one attempt. The probe runs on the login path the first
// time a key is installed, so a binary that hangs must not hold the login open until
// sshd's own LoginGraceTime kills it — the same bound, and for the same reason, as
// getentTimeout. A variable so the test for it does not have to wait.
var sshdProbeTimeout = 5 * time.Second

// sshdBannerLimit caps how much of the probed binary's output is kept. The banner is
// one short line; anything beyond this is a program that is not sshd, and reading it
// into the broker's memory is not required to find that out.
const sshdBannerLimit = 8 << 10

// sshdProbe is the result of asking the host what its sshd is.
//
// known is false whenever the answer is not positive evidence, and that is a state
// with its own behaviour rather than an error: see sshdSupportsKeyExpiry.
type sshdProbe struct {
	version sshdVersion
	known   bool
	// path is the binary the version came from, so that the refusal can name what it
	// looked at — the operator has to be able to tell a wrong probe from an old sshd.
	path string
	// why records, for the operator, every path that was tried and what each one did,
	// when no version could be established.
	why string
}

// sshdVersionProbe is how this package learns the local sshd's version. Only tests
// replace it; production has exactly one implementation.
var sshdVersionProbe = probeLocalSSHD

// sshdVersionCache memoizes the probe. Guarded by its own mutex because the first
// key installation of any account can reach it, and the broker installs keys from
// concurrent authentications.
var sshdVersionCache struct {
	sync.Mutex
	done   bool
	result sshdProbe
}

// localSSHDVersion returns the probe's answer, executing the probe at most once per
// process.
//
// Once per process rather than once per login because the answer is a property of an
// installed package: exec'ing a binary on every authentication would put a fork and
// an execve in the login path for a value that cannot change without a package
// upgrade. The cost of caching it is that an operator who upgrades OpenSSH under a
// running broker keeps being refused until the broker is restarted, which is why the
// refusal message says to restart it.
func localSSHDVersion() sshdProbe {
	sshdVersionCache.Lock()
	defer sshdVersionCache.Unlock()
	if !sshdVersionCache.done {
		sshdVersionCache.result = sshdVersionProbe()
		sshdVersionCache.done = true
		// Logged here, inside the once, so the operator gets exactly one line about the
		// host's sshd per broker lifetime instead of one per login.
		logSSHDProbe(sshdVersionCache.result)
	}
	return sshdVersionCache.result
}

// resetSSHDVersionCache drops the memoized answer. Tests use it; nothing in the
// broker does, because nothing in the broker may quietly re-decide this mid-run.
func resetSSHDVersionCache() {
	sshdVersionCache.Lock()
	defer sshdVersionCache.Unlock()
	sshdVersionCache.done = false
	sshdVersionCache.result = sshdProbe{}
}

// logSSHDProbe states what was found once, at the level the finding deserves.
func logSSHDProbe(probe sshdProbe) {
	switch {
	case !probe.known:
		// Loud, because this is the case where the broker goes on to install keys it
		// cannot vouch for. See sshdSupportsKeyExpiry for why it goes on.
		log.Warn().
			Str("required_openssh_version", minOpenSSHVersion).
			Str("probe_result", probe.why).
			Msg("Could not determine the local sshd version, so it cannot be confirmed that this " +
				"host honours the expiry-time= option on the keys the broker installs; on an sshd " +
				"older than the required version every installed key is rejected and logins fail " +
				"with 'Permission denied (publickey)'")
	case !probe.version.atLeast(minSSHDVersion):
		log.Error().
			Str("sshd_version", probe.version.String()).
			Str("sshd_path", probe.path).
			Str("required_openssh_version", minOpenSSHVersion).
			Msg("The local sshd is too old to honour the expiry-time= option the broker writes; " +
				"SSH key provisioning will be refused on this host until OpenSSH is upgraded")
	default:
		log.Info().
			Str("sshd_version", probe.version.String()).
			Str("sshd_path", probe.path).
			Msg("Local sshd honours the expiry-time= option on broker-issued keys")
	}
}

// sshdSupportsKeyExpiry returns an error when the local sshd is known to be too old
// to honour the expiry-time= option, and nil otherwise. The error is operator-facing:
// it is the only thing that will explain the refusal.
//
// (#199) An undetermined version is allowed through, and that asymmetry is the
// decision this function encodes. A version probe is a heuristic and not a fact: the
// binary found here is not necessarily the sshd that will authenticate the session
// (a container that ships no sshd at all but provisions into a shared home, a second
// sshd instance, an sshd installed outside sshdSearchPaths, an execve refused by
// SELinux or seccomp). Refusing on an undetermined version would therefore convert
// "the broker could not run a subprocess" into "nobody can log in to this host",
// for reasons that have nothing to do with the version — a self-inflicted outage,
// and one an operator cannot switch off, since this is not configurable.
//
// So the refusal rests on positive evidence only. What that leaves uncovered is a
// host that is genuinely too old *and* hides its sshd, and there the behaviour is
// v0.5.0's behaviour plus a warning that names the host as unverified — strictly
// better than today, and not a case worth an outage on every host where the probe
// simply cannot see the binary. Every platform in the README's supported table
// ships minOpenSSHVersion or newer, so nothing supported depends on this branch.
func sshdSupportsKeyExpiry() error {
	probe := localSSHDVersion()
	if !probe.known {
		return nil
	}
	if probe.version.atLeast(minSSHDVersion) {
		return nil
	}
	return fmt.Errorf("refusing to install an SSH key: the local sshd is OpenSSH %s (%s), and the "+
		"expiry-time= option that every entry this broker writes carries needs OpenSSH %s or newer. "+
		"An sshd that does not recognise an authorized_keys option refuses the whole entry, so the "+
		"key would be installed, this login would be reported as successful, and every SSH "+
		"authentication using that key would still fail with \"Permission denied (publickey)\". "+
		"Upgrade OpenSSH to %s or newer on this host and restart the broker, or run the broker on a "+
		"platform DEPLOYMENT.md lists as supported",
		probe.version, probe.path, minOpenSSHVersion, minOpenSSHVersion)
}

// probeLocalSSHD asks the host's sshd binary its version. This is the production
// sshdVersionProbe.
//
// The client is deliberately not consulted as a fallback. `ssh -V` is usually the
// same package's version, but it is a different program, and a refusal that rested
// on it would deny every login on a host whose client happens to be older than its
// daemon. Nothing here refuses on anything but the daemon's own banner.
func probeLocalSSHD() sshdProbe {
	tried := make([]string, 0, len(sshdSearchPaths))
	for _, path := range sshdSearchPaths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		banner, runErr := sshdVersionBanner(path)
		if runErr != nil {
			tried = append(tried, runErr.Error())
			continue
		}
		if version, ok := parseSSHDVersionBanner(banner); ok {
			return sshdProbe{version: version, known: true, path: path}
		}
		tried = append(tried, fmt.Sprintf("%s printed no OpenSSH version: %q", path, firstLine(banner)))
	}
	if len(tried) == 0 {
		return sshdProbe{why: "no sshd binary at " + strings.Join(sshdSearchPaths, ", ")}
	}
	return sshdProbe{why: strings.Join(tried, "; ")}
}

// sshdVersionBanner runs one sshd binary and returns whatever it printed.
//
// `-V` and never anything else. sshd started with no arguments *is* the daemon, so
// the argument list here is not a detail: -V either prints the version and exits, or
// is an option this sshd does not have, in which case sshd prints its usage — which
// begins with the same version banner — and exits non-zero. Both outcomes answer the
// question and neither starts a daemon.
//
// Both streams are captured for that second reason: the banner arrives on stderr on
// every sshd that predates `-V`, which is most of the range this check exists for.
// The exit status is ignored for the same reason; it is 1 exactly when the answer is
// most interesting.
func sshdVersionBanner(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshdProbeTimeout)
	defer cancel()

	// #nosec G204 -- path is one of sshdSearchPaths, a fixed list of absolute paths in
	// this file (a test hook, not configuration), and the only argument is a literal.
	cmd := exec.CommandContext(ctx, path, "-V")
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	// As in lookupViaGetent: cancelling the context kills the process but does not
	// close a pipe a surviving child inherited, and the wait is on the pipe. WaitDelay
	// makes it give up.
	cmd.WaitDelay = sshdProbeTimeout

	out := &cappedBuffer{limit: sshdBannerLimit}
	cmd.Stdout = out
	cmd.Stderr = out
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s -V did not answer within %s", path, sshdProbeTimeout)
	}
	banner := out.String()
	if strings.TrimSpace(banner) == "" {
		if runErr != nil {
			return "", fmt.Errorf("%s -V printed nothing: %v", path, runErr)
		}
		return "", fmt.Errorf("%s -V printed nothing", path)
	}
	return banner, nil
}

// cappedBuffer collects at most limit bytes of a subprocess's output and silently
// drops the rest. It claims to have written everything so that the subprocess is
// never handed a write error for output nobody wanted.
type cappedBuffer struct {
	buf   []byte
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		c.buf = append(c.buf, p[:room]...)
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return string(c.buf) }

// sshdBannerPrefix is how every OpenSSH release names itself, in `ssh -V`, in sshd's
// usage output and on the wire: "OpenSSH_9.6p1, OpenSSL 3.0.13".
const sshdBannerPrefix = "OpenSSH_"

// parseSSHDVersionBanner reads the OpenSSH version out of a version banner, wherever
// in the output it appears — an sshd that did not recognise `-V` prints a line of its
// own ("sshd: illegal option -- V") before the usage text the banner heads.
//
// Anything it cannot read is reported as unreadable rather than guessed at, and the
// caller treats that as an undetermined version. A misread version here is either a
// refused login on a host that would have worked or a silently broken key on a host
// that would not, so there is no benign wrong answer to fall back on.
func parseSSHDVersionBanner(banner string) (sshdVersion, bool) {
	rest := banner
	for {
		at := strings.Index(rest, sshdBannerPrefix)
		if at < 0 {
			return sshdVersion{}, false
		}
		rest = rest[at+len(sshdBannerPrefix):]
		if version, ok := parseSSHDVersionNumber(rest); ok {
			return version, true
		}
	}
}

// parseSSHDVersionNumber reads a leading "<major>.<minor>" and ignores whatever
// follows it: the portable suffix, a vendor's patch string, or the rest of a banner.
func parseSSHDVersionNumber(s string) (sshdVersion, bool) {
	major, rest, ok := leadingNumber(s)
	if !ok || !strings.HasPrefix(rest, ".") {
		return sshdVersion{}, false
	}
	minor, _, ok := leadingNumber(rest[1:])
	if !ok {
		return sshdVersion{}, false
	}
	return sshdVersion{major: major, minor: minor}, true
}

// leadingNumber reads the digits at the front of s. The length bound is what keeps a
// wall of digits from being read as a version number by a parser that would otherwise
// accept anything numeric; no OpenSSH release component has ever had more than two.
func leadingNumber(s string) (int, string, bool) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 || end > 4 {
		return 0, s, false
	}
	value, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0, s, false
	}
	return value, s[end:], true
}

// firstLine is what gets quoted back to the operator when a binary printed something
// that is not an OpenSSH banner: enough to recognise the program, not its whole
// usage message.
func firstLine(s string) string {
	line := strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if len(line) > 120 {
		return line[:120] + "..."
	}
	return line
}
