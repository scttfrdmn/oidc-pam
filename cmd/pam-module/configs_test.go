package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// These tests read the files this repository ships and assert properties of
// them. They carry no build tag on purpose: they need no cgo, and the stacks are
// worth pinning on a developer's Mac too.

const (
	pamConfigsDir = "../../configs/pam"
	repoRoot      = "../.."
)

// pamStack is one shipped file from configs/pam: the path to it, the
// /etc/pam.d/<service> name PAM would know it by, and its lines.
type pamStack struct {
	path  string
	name  string
	lines []string
}

// interactivePAMServices are the only services a shipped stack may wire
// pam_oidc.so into. Each is a login a person starts and then waits for, so the
// device-flow instructions have a terminal to be printed on and someone in front
// of it to read them. Adding a name here is a claim that its PAM conversation
// reaches a human who can finish a device flow inside `timeout` (90 s by
// default) — not a claim that it has been tested; only `ssh` is, by test/e2e.
var interactivePAMServices = map[string]string{
	"ssh":   "sshd, over keyboard-interactive",
	"login": "console getty login on a tty",
	"su":    "run from a shell, on that shell's terminal",
	"sudo":  "run from a shell, on that shell's terminal",
}

// aggregatePAMStacks are the files every PAM service on the host runs by way of
// @include or pam_stack. A module in one of these is a module in the auth stack
// of su, sudo, the display manager, polkit, cron and everything else linked
// against libpam — including the callers that can never satisfy a device flow
// because they have no controlling terminal, discard PAM_TEXT_INFO, or would
// render the QR code as a block of ASCII art in a graphical prompt. This
// project's module belongs in per-service files only (#172).
var aggregatePAMStacks = map[string]string{
	"common-auth":     "Debian/Ubuntu",
	"common-account":  "Debian/Ubuntu",
	"common-session":  "Debian/Ubuntu",
	"common-password": "Debian/Ubuntu",
	"system-auth":     "RHEL/Fedora/SUSE",
	"system-auth-ac":  "RHEL (authconfig)",
	"password-auth":   "RHEL/Fedora",
	"postlogin":       "RHEL/Fedora",
	"smartcard-auth":  "RHEL/Fedora",
}

// pamStackFiles returns every stack file under configs/pam. README.md documents
// the stacks and is not one of them.
func pamStackFiles(t *testing.T) []pamStack {
	t.Helper()

	entries, err := os.ReadDir(pamConfigsDir)
	if err != nil {
		t.Fatalf("read %s: %v", pamConfigsDir, err)
	}

	var stacks []pamStack
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".md") {
			continue
		}

		path := filepath.Join(pamConfigsDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		stacks = append(stacks, pamStack{
			path:  path,
			name:  entry.Name(),
			lines: strings.Split(string(content), "\n"),
		})
	}

	if len(stacks) == 0 {
		t.Fatalf("found no stack files under %s; these tests are checking nothing", pamConfigsDir)
	}
	return stacks
}

// pamDirective splits an active PAM line into its phase, control flag and module.
// ok is false for blank lines and comments. A bracketed control flag comes back
// whole, brackets included ("[success=2 default=ignore]"), so a caller can name
// it in an error message.
func pamDirective(line string) (phase, control, module string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
		return "", "", "", false
	}

	phase, rest := fields[0], fields[1:]

	if strings.HasPrefix(rest[0], "[") {
		end := -1
		for i, field := range rest {
			if strings.HasSuffix(field, "]") {
				end = i
				break
			}
		}
		if end == -1 {
			return phase, strings.Join(rest, " "), "", true
		}
		control, rest = strings.Join(rest[:end+1], " "), rest[end+1:]
	} else {
		control, rest = rest[0], rest[1:]
	}

	if len(rest) > 0 {
		module = rest[0]
	}
	return phase, control, module, true
}

// The PAM stacks in configs/pam must not pass `debug`.
//
// `debug` makes the module log the details of every authentication that service
// handles to LOG_AUTHPRIV — before #168, that included the broker's entire
// response, device code and instructions and all. The shipped ssh and login stacks
// passed it, so every host built by copying them into /etc/pam.d logged that on
// every login; the ssh config even carried a note telling the reader to take it
// out again. It is a diagnostic an operator turns on while watching a login, not a
// default.
func TestShippedPAMStacksDoNotEnableDebug(t *testing.T) {
	moduleLines := 0

	for _, stack := range pamStackFiles(t) {
		for i, line := range stack.lines {
			fields := strings.Fields(line)
			if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			if !strings.Contains(line, "pam_oidc.so") {
				continue
			}
			moduleLines++

			for _, field := range fields {
				if field == "debug" {
					t.Errorf("%s:%d ships `debug`, so every login this stack handles logs its "+
						"details to LOG_AUTHPRIV: %s", stack.path, i+1, strings.TrimSpace(line))
				}
			}
		}
	}

	if moduleLines == 0 {
		t.Fatalf("found no pam_oidc.so lines under %s; this test is checking nothing", pamConfigsDir)
	}
}

// Every shipped stack must be a single service's /etc/pam.d file, and that
// service must be one a person can finish a device flow on.
//
// configs/pam/common-auth used to break this: it is the file every Debian/Ubuntu
// service @includes, so copying it into place put `pam_oidc.so` at the front of
// the auth stack of su, sudo, gdm/sddm, polkit and cron — each of which then
// waited up to `timeout` seconds (90 by default) for a human with a phone,
// several of them with no way to show that human the verification URL, and then
// fell through. Nothing was let in that should not have been (the stacks fail
// closed), but the host became unusable, and with no password fallback in the
// shipped stacks (#160) an unusable auth stack is an operator locked out of their
// own machine.
func TestShippedPAMStacksAreServiceScoped(t *testing.T) {
	// As in TestDocsReferenceOnlyShippedPAMStacks: a trailing full stop is
	// punctuation, not part of the service name.
	pamdPath := regexp.MustCompile(`/etc/pam\.d/([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)`)

	for _, stack := range pamStackFiles(t) {
		if distro, aggregate := aggregatePAMStacks[stack.name]; aggregate {
			t.Errorf("%s is the %s stack that every service on the host @includes: shipping it "+
				"puts an interactive device flow in the auth stack of su, sudo, the display "+
				"manager, polkit and cron. Ship a per-service file instead (one of %s).",
				stack.path, distro, sortedNames(interactivePAMServices))
			continue
		}
		if _, ok := interactivePAMServices[stack.name]; !ok {
			t.Errorf("%s is not one of the services that can complete a device flow (%s). A stack "+
				"for a new service needs a terminal the module can print the verification URL to "+
				"and a user waiting on it; add it to interactivePAMServices with the reason if so.",
				stack.path, sortedNames(interactivePAMServices))
		}

		for i, line := range stack.lines {
			// A stack file's header says where to install it, and its notes
			// point at other services' files. No such path may be a host-wide
			// stack — the misleading comment is half of this defect.
			for _, match := range pamdPath.FindAllStringSubmatch(line, -1) {
				if distro, aggregate := aggregatePAMStacks[match[1]]; aggregate {
					t.Errorf("%s:%d points at /etc/pam.d/%s, the %s stack every service "+
						"@includes: %s", stack.path, i+1, match[1], distro, strings.TrimSpace(line))
				}
			}

			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "@include" {
				continue
			}
			if distro, aggregate := aggregatePAMStacks[fields[1]]; aggregate {
				t.Errorf("%s:%d @includes the %s host-wide stack, which ties this service's auth "+
					"decision back to a file shared with every other service: %s",
					stack.path, i+1, distro, strings.TrimSpace(line))
			}
		}
	}
}

// The control flag decides what PAM does with the module's answer, so the
// shipped stacks may only use the flags configs/pam/README.md documents:
//
//   - auth: `sufficient` or `required`. This is the module's one real decision.
//   - account: `optional` only. pam_sm_acct_mgmt returns PAM_IGNORE, and
//     `account sufficient` once let a PAM_SUCCESS there short-circuit every
//     account check after it (#122).
//   - session, password: `optional`. The module logs, and cannot change a
//     password — as `required` it would block password changes for local
//     accounts too.
//
// Bracketed flags are refused outright: `[success=2 default=ignore]`, which
// configs/pam/common-auth used, encodes "skip the next two modules" as a number
// that silently means something else the moment a line is added or removed.
func TestShippedPAMStacksUseDocumentedControlFlags(t *testing.T) {
	allowed := map[string][]string{
		"auth":     {"sufficient", "required"},
		"account":  {"optional"},
		"session":  {"optional"},
		"password": {"optional"},
	}

	checked := 0
	for _, stack := range pamStackFiles(t) {
		for i, line := range stack.lines {
			phase, control, module, ok := pamDirective(line)
			if !ok || module != "pam_oidc.so" {
				continue
			}
			checked++

			flags, known := allowed[phase]
			if !known {
				t.Errorf("%s:%d uses unknown PAM phase %q: %s", stack.path, i+1, phase,
					strings.TrimSpace(line))
				continue
			}
			if strings.HasPrefix(control, "[") {
				t.Errorf("%s:%d controls pam_oidc.so with %s; the shipped stacks use the plain "+
					"flags (%s for %s) so that adding a line cannot change what a skip count "+
					"means: %s", stack.path, i+1, control, strings.Join(flags, " or "), phase,
					strings.TrimSpace(line))
				continue
			}
			if !slices.Contains(flags, control) {
				t.Errorf("%s:%d is `%s %s pam_oidc.so`; %s must be %s. See configs/pam/README.md.",
					stack.path, i+1, phase, control, phase, strings.Join(flags, " or "))
			}
		}
	}

	if checked == 0 {
		t.Fatalf("found no pam_oidc.so directives under %s; this test is checking nothing",
			pamConfigsDir)
	}
}

// printsAdvice matches a shell line whose only effect is to put text on the
// operator's terminal: one of this repo's print_* helpers, or echo/printf, with no
// redirection or pipe that could send the text into a file instead.
//
// Such a line may name a host-wide stack. Telling an operator to put `@include
// common-auth` back into /etc/pam.d/sshd — which is what scripts/uninstall.sh does
// when it has no pre-install backup to restore — is the correct instruction, and it
// is the opposite of the defect TestInstallScriptsDoNotTouchAggregatePAMStacks
// exists to catch: it restores the distribution's own include in a *service* file
// rather than editing the aggregate one.
var printsAdvice = regexp.MustCompile(`^\s*(print_(info|warn|error|success|step)|echo|printf)\b[^|>]*$`)

// No install path may wire pam_oidc.so into a host-wide stack.
//
// scripts/install.sh used to insert `@include common-auth` at the top of
// /etc/pam.d/sshd, next to the pam_oidc.so line it adds — which both duplicated
// the distribution's own include further down the file and, on a host where an
// operator had followed the old configs/pam/common-auth advice, ran the device
// flow twice.
func TestInstallScriptsDoNotTouchAggregatePAMStacks(t *testing.T) {
	scripts, err := filepath.Glob(filepath.Join(repoRoot, "scripts", "*.sh"))
	if err != nil {
		t.Fatalf("glob scripts: %v", err)
	}
	if len(scripts) == 0 {
		t.Fatal("found no scripts/*.sh; this test is checking nothing")
	}

	for _, script := range scripts {
		content, err := os.ReadFile(script)
		if err != nil {
			t.Fatalf("read %s: %v", script, err)
		}
		for i, line := range strings.Split(string(content), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			// A line that only prints is guidance, not an edit. Anything that
			// redirects, pipes, or calls sed/cp/tee still trips this, because those
			// are the shapes that can write to a file.
			if printsAdvice.MatchString(line) {
				continue
			}
			for name, distro := range aggregatePAMStacks {
				if strings.Contains(line, name) {
					t.Errorf("%s:%d touches the %s host-wide PAM stack %q: an installer must "+
						"only edit the /etc/pam.d file of the service the operator asked for, "+
						"never the one every service @includes: %s",
						script, i+1, distro, name, strings.TrimSpace(line))
				}
			}
		}
	}
}

// Every configs/pam file a document or script names must exist. The stacks and
// the instructions for installing them are edited separately, so a deleted stack
// leaves an operator copying a file that is not there — or, worse, believing the
// project still endorses it. CHANGELOG.md is excluded: it records what past
// releases shipped, including files since removed.
func TestDocsReferenceOnlyShippedPAMStacks(t *testing.T) {
	// Each dot in the file name must be followed by more name, so a reference at
	// the end of a sentence does not capture the full stop.
	reference := regexp.MustCompile(`configs/pam/([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)`)

	docs, err := filepath.Glob(filepath.Join(repoRoot, "*.md"))
	if err != nil {
		t.Fatalf("glob docs: %v", err)
	}
	scripts, err := filepath.Glob(filepath.Join(repoRoot, "scripts", "*.sh"))
	if err != nil {
		t.Fatalf("glob scripts: %v", err)
	}
	files := append(docs, scripts...)
	files = append(files,
		filepath.Join(pamConfigsDir, "README.md"),
		filepath.Join(repoRoot, "docs", "design", "README.md"),
	)

	found := 0
	for _, file := range files {
		if filepath.Base(file) == "CHANGELOG.md" {
			continue
		}
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for i, line := range strings.Split(string(content), "\n") {
			for _, match := range reference.FindAllStringSubmatch(line, -1) {
				found++
				path := filepath.Join(pamConfigsDir, match[1])
				if _, err := os.Stat(path); err != nil {
					t.Errorf("%s:%d refers to configs/pam/%s, which this repository does not "+
						"ship: %s", file, i+1, match[1], strings.TrimSpace(line))
				}
			}
		}
	}

	if found == 0 {
		t.Fatal("found no configs/pam references in the documentation; this test is checking nothing")
	}
}

// sortedNames renders a name set for an error message, in a stable order.
func sortedNames(set map[string]string) string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}
