package auth

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// TestShippedConfigsStartAPolicyEngine closes the gap that #212's fix opened.
//
// pkg/config's TestShippedConfigsLoad already loads and validates every file under
// configs/, but loading is not starting: since v0.5.1 the broker also refuses a
// configuration whose access controls it cannot enforce, and that check lives in
// pkg/auth. So a shipped template could pass the existing gate and still stop the
// broker on the operator's host — which is exactly what every one of these files
// did the moment the check was added, because between them they set nine
// unenforceable policy keys, two risk actions the broker does not perform, and two
// risk conditions naming flags that have never existed.
//
// The engine is built through NewPolicyEngine, the same call cmd/broker makes, so
// this fails for anything that would have failed at startup: an unsupported key, an
// unparseable risk condition, a time restriction scoped to no provider, a country
// restriction with no GeoIP database, or a GeoIP database path that does not exist.
func TestShippedConfigsStartAPolicyEngine(t *testing.T) {
	// configs/providers/aws-identity-center.yaml resolves an env: secret reference.
	t.Setenv("OIDC_CLIENT_SECRET", "test-client-secret")
	// These are production templates: no development-mode relaxations.
	t.Setenv("OIDC_AUTH_DEV", "")

	root := filepath.Join("..", "..")
	files := wholeConfigsUnder(t, filepath.Join(root, "configs"))
	if len(files) == 0 {
		t.Fatal("no whole broker configurations found under configs/ — this gate would pass vacuously")
	}
	// The end-to-end harness's configuration, which is only ever loaded inside a
	// Linux container and so has no other chance to be checked on this host.
	if e2e := filepath.Join(root, "test", "e2e", "broker.yaml"); isWholeConfigFile(e2e) {
		files = append(files, e2e)
	}

	for _, file := range files {
		name, err := filepath.Rel(root, file)
		if err != nil {
			name = file
		}
		t.Run(name, func(t *testing.T) {
			// LoadConfig refuses a file anyone but its owner can read (#209), and a
			// file in the repository is 0644; the mode is pkg/config's gate, the
			// content is this one's.
			cfg, err := config.LoadConfig(copyAt0600(t, file))
			if err != nil {
				t.Fatalf("%s does not load: %v", name, err)
			}

			engine, err := NewPolicyEngine(cfg)
			if err != nil {
				t.Fatalf("%s loads but will not start a broker: %v", name, err)
			}
			engine.Close()
		})
	}
}

// TestNoUnenforceablePolicyKeyInAnyShippedFile keeps the refused keys out of the
// YAML this repository ships and the documents an operator pastes from, including
// the ones no test loads. A key that is only wrong in a commented-out example is
// still a key someone uncomments; the point of the comments left behind in those
// files is that they say why, and this gate is what stops a live one reappearing.
func TestNoUnenforceablePolicyKeyInAnyShippedFile(t *testing.T) {
	// The ten keys validatePolicySupport refuses, plus the two risk actions. Read
	// as YAML keys and values, so the prose in CONFIGURATION-GUIDE.md that has to
	// name them in order to tell an operator to remove them still passes.
	refusedKeys := []string{
		"require_reauth_for_new_hosts",
		"require_institutional_affiliation",
		"require_allocation_verification",
		"require_project_membership",
		"audit_level",
		"allow_untrusted_devices",
		"require_additional_mfa",
		"no_data_export",
		"session_recording",
		"require_approval_for",
	}
	refusedActions := []string{"REQUIRE_ADDITIONAL_MFA", "REQUIRE_APPROVAL"}

	// docs/design/ is excluded, as it is in pkg/config's documentation gate: it is
	// marked unmaintained in docs/design/README.md and describes a product that was
	// never built, including all ten of these settings.
	roots := []string{"configs", "QUICK-START.md", "DEPLOYMENT.md", "README.md"}

	checked := 0
	for _, root := range roots {
		err := filepath.WalkDir(filepath.Join("..", "..", root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			switch filepath.Ext(path) {
			case ".yaml", ".yml", ".md":
			default:
				return nil
			}
			data, err := os.ReadFile(path) // #nosec G304 -- walking a fixed repo-relative root
			if err != nil {
				return err
			}
			checked++
			rel := strings.TrimPrefix(path, filepath.Join("..", "..")+string(filepath.Separator))
			for i, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					// A commented example is where these now live, with the
					// explanation of why they are commented.
					continue
				}
				for _, key := range refusedKeys {
					if strings.HasPrefix(trimmed, key+":") {
						t.Errorf("%s:%d sets %s, which the broker refuses to start on because "+
							"nothing enforces it (#212)", rel, i+1, key)
					}
				}
				// Matched as a YAML `action:` value rather than anywhere on the
				// line: the guide has to be able to name these in prose in order
				// to tell an operator to remove them, and naming them is what an
				// operator searches for after the broker refuses to start.
				if value, isAction := strings.CutPrefix(trimmed, "action:"); isAction {
					value = strings.Trim(strings.TrimSpace(value), `"'`)
					for _, action := range refusedActions {
						if value == action {
							t.Errorf("%s:%d sets the risk action %s, which the broker refuses to "+
								"start on: it performs DENY and LOG (#212)", rel, i+1, action)
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("failed to walk %s: %v", root, err)
		}
	}
	if checked == 0 {
		t.Fatal("no configuration or documentation files were read — this gate would pass vacuously")
	}
}

// wholeConfigsUnder returns the YAML files under root that are rooted at the top
// level of a broker configuration. A provider fragment is skipped: it holds a
// single oidc.providers entry and no authentication section, so there is no policy
// for an engine to compile.
func wholeConfigsUnder(t *testing.T, root string) []string {
	t.Helper()

	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if isWholeConfigFile(path) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", root, err)
	}
	return files
}

// isWholeConfigFile reports whether path parses as YAML and carries at least one
// section of a broker configuration.
func isWholeConfigFile(path string) bool {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		return false
	}
	for _, section := range []string{"server", "oidc", "authentication", "security", "audit"} {
		if v.IsSet(section) {
			return true
		}
	}
	return false
}

// copyAt0600 copies a configuration to a file only its owner can read, which is
// the mode LoadConfig requires (#209) and the mode the installers give it.
func copyAt0600(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path) // #nosec G304 -- a path this test just walked to
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	dst := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.WriteFile(dst, data, 0600); err != nil {
		t.Fatalf("failed to write %s: %v", dst, err)
	}
	return dst
}
