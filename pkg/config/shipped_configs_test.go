// Package config_test holds the tests that need the packages which read a
// configuration (pkg/security), and so cannot live in package config itself.
package config_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
)

// repoRoot locates the shipped configuration relative to this package.
const repoRoot = "../.."

// topLevelSections are the sections a whole broker configuration is made of.
// Kept in step with the fields of config.Config.
var topLevelSections = map[string]bool{
	"server":         true,
	"oidc":           true,
	"authentication": true,
	"security":       true,
	"audit":          true,
}

// TestShippedConfigsLoad is the gate for #170: every configuration file this
// repository ships is loaded, validated, and its audit configuration checked,
// exactly as the broker would at startup.
//
// Nothing had ever done this. broker-cloud.yaml could not be parsed at all (it
// used ${VAR:-default} shell interpolation, which nothing expands),
// broker-enterprise.yaml named audit output types that do not exist and so was
// fatal at startup, and both carried whole sections — ssh:, policy:, cloud: —
// that no field reads. All three shipped for eleven releases and two of them
// are recommended as templates by CONFIGURATION-GUIDE.md.
func TestShippedConfigsLoad(t *testing.T) {
	// configs/providers/aws-identity-center.yaml carries "env:" secret
	// references, which LoadConfig resolves, so the variable has to exist.
	t.Setenv("OIDC_CLIENT_SECRET", "test-client-secret")
	// These are production templates: they must load with no development-mode
	// relaxations in force.
	t.Setenv("OIDC_AUTH_DEV", "")

	files := yamlFilesUnder(t, filepath.Join(repoRoot, "configs"))
	if len(files) == 0 {
		t.Fatal("no YAML files found under configs/ — this gate would pass vacuously")
	}
	// The end-to-end harness's broker configuration, which only ever gets loaded
	// inside a Linux container. It carried a `format` key on each audit output
	// that no field reads, so it too would have failed to start.
	files = append(files, filepath.Join(repoRoot, "test", "e2e", "broker.yaml"))

	for _, file := range files {
		name, err := filepath.Rel(repoRoot, file)
		if err != nil {
			name = file
		}
		t.Run(name, func(t *testing.T) {
			path := file
			if !isWholeConfig(t, file) {
				path = wrapProviderFragment(t, file)
			}
			// LoadConfig refuses a configuration anyone but root can read (#209),
			// and a file in the repository is 0644. What this gate is about is the
			// content, so it is read from a copy with the mode the installers now
			// give it; TestLoadConfigRejectsWorldReadableFile covers the mode.
			path = copyAt0600(t, path)

			cfg, err := config.LoadConfig(path)
			if err != nil {
				t.Fatalf("%s does not load: %v", name, err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("%s does not validate: %v", name, err)
			}
			// The broker passes this straight to security.NewAuditLogger, whose
			// error reaches log.Fatal in cmd/broker. Checked rather than
			// constructed so the test neither writes to /var/log nor needs a
			// syslog daemon.
			if err := security.ValidateAuditConfig(cfg.Audit); err != nil {
				t.Fatalf("%s would kill the broker at startup: %v", name, err)
			}
		})
	}
}

// TestDocumentedConfigSnippetsLoad holds the YAML in the operator-facing
// documents to the same standard as the shipped files, because a key that is
// only wrong in a document is still a key an operator pastes into
// /etc/oidc-auth/broker.yaml. QUICK-START.md and DEPLOYMENT.md both documented
// a `logging:` block and a `security.encryption_key` that no field reads (#170),
// and DEPLOYMENT.md's policy example listed three non-existent policy fields
// until #158.
//
// docs/design/ is deliberately excluded: it is marked unmaintained in
// docs/design/README.md and describes behaviour that was never built.
func TestDocumentedConfigSnippetsLoad(t *testing.T) {
	t.Setenv("OIDC_CLIENT_SECRET", "test-client-secret")
	// Documentation may legitimately show a development-only setting
	// (skip_tls_verify), so snippets are read in the mode that permits every
	// documented setting. What is under test here is which keys exist.
	t.Setenv("OIDC_AUTH_DEV", "true")

	docs := []string{
		"README.md",
		"QUICK-START.md",
		"DEPLOYMENT.md",
		"configs/CONFIGURATION-GUIDE.md",
	}

	checked := 0
	for _, doc := range docs {
		for _, snippet := range yamlSnippets(t, filepath.Join(repoRoot, doc)) {
			path := snippet.write(t)
			if !isWholeConfig(t, path) {
				// A snippet rooted below the top level (a bare user_mapping:
				// block, say) or one that is not YAML at all cannot be loaded as
				// a configuration; only whole-config-rooted blocks are checked.
				continue
			}
			checked++
			t.Run(snippet.name(), func(t *testing.T) {
				// Validate() is not called: a snippet shows part of a
				// configuration and is not required to be complete.
				_, err := config.LoadConfig(path)
				if err != nil && !isUnresolvableSecret(err) {
					t.Fatalf("the YAML at %s:%d does not load: %v", doc, snippet.line, err)
				}
			})
		}
	}
	if checked == 0 {
		t.Fatal("no configuration YAML found in the operator documentation — this gate would pass vacuously")
	}
}

// misspelledPinningKey matches `pin_certificates` written as a YAML key, which
// is what an operator copies. Prose about the misspelling is deliberately
// allowed: the guide has to be able to name the key, since naming it is what an
// operator searches for after the broker refuses to start.
var misspelledPinningKey = regexp.MustCompile(`(?m)^\s*pin_certificates\s*:`)

// TestNoMisspelledCertificatePinningKey covers the acceptance criterion of #170
// for `pin_certificates`, which is not the name of any field: the setting is
// `security.tls_verification.pinned_certificates`, and it takes a list of
// SHA-256 fingerprints rather than a boolean. It appeared in six files, as
// `true` in three of them, so every operator following the shipped
// configuration or the guide believed they had certificate pinning on and had
// nothing of the kind. Writing it is now a startup error, but the files that
// taught it must not come back either — including the design notes under docs/,
// which nothing else here reads.
func TestNoMisspelledCertificatePinningKey(t *testing.T) {
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		// Configuration and documentation: those are the files whose keys get
		// pasted into /etc/oidc-auth/broker.yaml.
		switch filepath.Ext(path) {
		case ".yaml", ".yml", ".md":
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			if misspelledPinningKey.MatchString(line) {
				rel, _ := filepath.Rel(repoRoot, path)
				t.Errorf("%s:%d sets a key no field reads; certificate pinning is "+
					"security.tls_verification.pinned_certificates and takes a list of "+
					"SHA-256 fingerprints (#170)", rel, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk the repository: %v", err)
	}
}

// isUnresolvableSecret reports whether the only thing wrong with a snippet is
// that it points at a secret file or environment variable belonging to the
// operator's host. LoadConfig resolves secrets only after decoding, so an
// unknown key is always reported first and tolerating this cannot hide one.
func isUnresolvableSecret(err error) bool {
	return strings.Contains(err.Error(), "failed to resolve secret references")
}

// copyAt0600 copies a configuration to a temporary file the broker will accept,
// i.e. one only its owner can read.
func copyAt0600(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	dst := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.WriteFile(dst, data, 0600); err != nil {
		t.Fatalf("failed to write %s: %v", dst, err)
	}
	return dst
}

func yamlFilesUnder(t *testing.T, root string) []string {
	t.Helper()

	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", root, err)
	}
	return files
}

// isWholeConfig reports whether a file parses as YAML and is rooted at the top
// level of a broker configuration, i.e. carries at least one known section.
func isWholeConfig(t *testing.T, path string) bool {
	t.Helper()

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		return false
	}
	for key := range v.AllSettings() {
		if topLevelSections[key] {
			return true
		}
	}
	return false
}

// wrapProviderFragment loads a file that is a single oidc.providers entry rather
// than a whole configuration — configs/providers/aws-identity-center.yaml is one
// — by wrapping it in the smallest configuration that can hold it. Wrapping
// rather than skipping: a file the gate skips is a file free to rot, and the
// keys of a provider entry are exactly what this gate is about.
func wrapProviderFragment(t *testing.T, path string) string {
	t.Helper()

	in := viper.New()
	in.SetConfigFile(path)
	in.SetConfigType("yaml")
	if err := in.ReadInConfig(); err != nil {
		t.Fatalf("%s is neither a whole configuration nor parseable YAML: %v", path, err)
	}

	out := viper.New()
	out.Set("oidc.providers", []any{in.AllSettings()})
	wrapped := filepath.Join(t.TempDir(), "wrapped-"+filepath.Base(path))
	if err := out.WriteConfigAs(wrapped); err != nil {
		t.Fatalf("failed to wrap %s as a configuration: %v", path, err)
	}
	return wrapped
}

// docSnippet is one ```yaml fenced block from a Markdown document.
type docSnippet struct {
	doc  string
	line int // 1-based line of the opening fence
	body []byte
}

func (s docSnippet) name() string {
	return filepath.Base(s.doc) + ":" + strconv.Itoa(s.line)
}

// write puts the snippet in a temporary file, since LoadConfig takes a path.
func (s docSnippet) write(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "snippet.yaml")
	if err := os.WriteFile(path, s.body, 0600); err != nil {
		t.Fatalf("failed to write snippet from %s:%d: %v", s.doc, s.line, err)
	}
	return path
}

func yamlSnippets(t *testing.T, doc string) []docSnippet {
	t.Helper()

	data, err := os.ReadFile(doc)
	if err != nil {
		t.Fatalf("failed to read %s: %v", doc, err)
	}

	var snippets []docSnippet
	var current *docSnippet
	for i, line := range strings.Split(string(data), "\n") {
		fence := strings.TrimSpace(line)
		switch {
		case current == nil && fence == "```yaml":
			snippets = append(snippets, docSnippet{doc: doc, line: i + 1})
			current = &snippets[len(snippets)-1]
		case current != nil && fence == "```":
			current = nil
		case current != nil:
			current.body = append(current.body, []byte(line+"\n")...)
		}
	}
	if current != nil {
		t.Fatalf("%s has an unterminated ```yaml block at line %d", doc, current.line)
	}
	return snippets
}
