package metrics_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"

	"github.com/scttfrdmn/oidc-pam/pkg/metrics"
)

// newTestMetrics creates a Metrics instance using an isolated registry.
func newTestMetrics(t *testing.T) (*metrics.Metrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, nil)
	return m, reg
}

// counterValue reads the current value of a counter/gauge with the given
// labels from the registry.
func counterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m, labels) {
				switch mf.GetType() {
				case dto.MetricType_COUNTER:
					return m.GetCounter().GetValue()
				case dto.MetricType_GAUGE:
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	return 0
}

// histogramCount reads the sample count of a histogram from the registry.
func histogramCount(t *testing.T, reg *prometheus.Registry, name string) uint64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			for _, m := range mf.GetMetric() {
				return m.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

// labelsMatch reports whether all entries in want appear in the metric labels.
func labelsMatch(m *dto.Metric, want map[string]string) bool {
	got := make(map[string]string, len(m.GetLabel()))
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// TestMetricsNew verifies that New returns a fully populated Metrics struct.
func TestMetricsNew(t *testing.T) {
	m, _ := newTestMetrics(t)

	if m.AuthAttempts == nil {
		t.Error("AuthAttempts is nil")
	}
	if m.ActiveSessions == nil {
		t.Error("ActiveSessions is nil")
	}
	if m.PolicyEvaluations == nil {
		t.Error("PolicyEvaluations is nil")
	}
	if m.RiskScore == nil {
		t.Error("RiskScore is nil")
	}
	if m.SSHKeyOperations == nil {
		t.Error("SSHKeyOperations is nil")
	}
}

// TestMetricsNewWithDroppedEventsFunc verifies that a droppedEventsFn causes
// oidc_audit_events_dropped_total to be registered and returns the correct value.
func TestMetricsNewWithDroppedEventsFunc(t *testing.T) {
	reg := prometheus.NewRegistry()
	var dropped float64 = 7
	_ = metrics.New(reg, func() float64 { return dropped })

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "oidc_audit_events_dropped_total" {
			v := mf.GetMetric()[0].GetGauge().GetValue()
			if v != dropped {
				t.Errorf("Expected %v for dropped total, got %v", dropped, v)
			}
			return
		}
	}
	t.Error("Expected oidc_audit_events_dropped_total metric to be registered")
}

// TestMetricsNewNoDroppedEventsFunc verifies that omitting droppedEventsFn
// does not register oidc_audit_events_dropped_total.
func TestMetricsNewNoDroppedEventsFunc(t *testing.T) {
	_, reg := newTestMetrics(t) // nil droppedEventsFn

	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() == "oidc_audit_events_dropped_total" {
			t.Error("Expected oidc_audit_events_dropped_total NOT to be registered when droppedEventsFn is nil")
		}
	}
}

// TestRecordAuth verifies that RecordAuth increments AuthAttempts with correct labels.
func TestRecordAuth(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.RecordAuth("test-provider", "success", "")
	m.RecordAuth("test-provider", "success", "")
	m.RecordAuth("test-provider", "failure", "DEVICE_EXPIRED")
	m.RecordAuth("", "policy_denied", "POLICY_DENIED")

	cases := []struct {
		provider  string
		result    string
		errorCode string
		want      float64
	}{
		{"test-provider", "success", "", 2},
		{"test-provider", "failure", "DEVICE_EXPIRED", 1},
		{"", "policy_denied", "POLICY_DENIED", 1},
	}
	for _, c := range cases {
		got := counterValue(t, reg, "oidc_auth_attempts_total", map[string]string{
			"provider":   c.provider,
			"result":     c.result,
			"error_code": c.errorCode,
		})
		if got != c.want {
			t.Errorf("RecordAuth(%q,%q,%q): want %v, got %v",
				c.provider, c.result, c.errorCode, c.want, got)
		}
	}
}

// TestActiveSessions verifies gauge increments and decrements.
func TestActiveSessions(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.ActiveSessions.Inc()
	m.ActiveSessions.Inc()
	m.ActiveSessions.Inc()
	m.ActiveSessions.Dec()

	got := counterValue(t, reg, "oidc_active_sessions", nil)
	if got != 2 {
		t.Errorf("Expected active_sessions=2, got %v", got)
	}
}

// TestActiveSessionsNeverNegative verifies the gauge doesn't go below zero
// under a sequence of Inc/Dec calls matching typical session lifecycle.
func TestActiveSessionsNeverNegative(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.ActiveSessions.Inc()
	m.ActiveSessions.Dec()

	got := counterValue(t, reg, "oidc_active_sessions", nil)
	if got < 0 {
		t.Errorf("active_sessions gauge should not be negative, got %v", got)
	}
}

// TestRecordPolicyEval verifies allowed/denied counters and risk score histogram.
func TestRecordPolicyEval(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.RecordPolicyEval(true, 30)
	m.RecordPolicyEval(true, 50)
	m.RecordPolicyEval(false, 80)

	if got := counterValue(t, reg, "oidc_policy_evaluations_total", map[string]string{"result": "allowed"}); got != 2 {
		t.Errorf("Expected 2 allowed evaluations, got %v", got)
	}
	if got := counterValue(t, reg, "oidc_policy_evaluations_total", map[string]string{"result": "denied"}); got != 1 {
		t.Errorf("Expected 1 denied evaluation, got %v", got)
	}
	if n := histogramCount(t, reg, "oidc_risk_score"); n != 3 {
		t.Errorf("Expected 3 risk score observations, got %d", n)
	}
}

// TestRecordSSHKeyOp verifies SSH key operation counters.
func TestRecordSSHKeyOp(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.RecordSSHKeyOp("generate", "success")
	m.RecordSSHKeyOp("generate", "success")
	m.RecordSSHKeyOp("generate", "failure")
	m.RecordSSHKeyOp("revoke", "success")

	cases := []struct {
		op     string
		result string
		want   float64
	}{
		{"generate", "success", 2},
		{"generate", "failure", 1},
		{"revoke", "success", 1},
	}
	for _, c := range cases {
		got := counterValue(t, reg, "oidc_ssh_key_operations_total", map[string]string{
			"operation": c.op,
			"result":    c.result,
		})
		if got != c.want {
			t.Errorf("RecordSSHKeyOp(%q,%q): want %v, got %v", c.op, c.result, c.want, got)
		}
	}
}

// TestMetricsHTTPEndpoint verifies that the /metrics HTTP endpoint returns a
// 200 response containing at least one registered metric name after observations.
func TestMetricsHTTPEndpoint(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, nil)

	// Generate some observations so the metric families show up in the output.
	m.RecordAuth("prov", "success", "")
	m.RecordPolicyEval(true, 40)
	m.RecordSSHKeyOp("generate", "success")

	ts := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	for _, name := range []string{
		"oidc_auth_attempts_total",
		"oidc_policy_evaluations_total",
		"oidc_ssh_key_operations_total",
	} {
		if !strings.Contains(bodyStr, name) {
			t.Errorf("Expected %q in /metrics response", name)
		}
	}
}

// TestDroppedEventsFnUpdates verifies that a changing droppedEventsFn value is
// reflected in subsequent Gather calls.
func TestDroppedEventsFnUpdates(t *testing.T) {
	reg := prometheus.NewRegistry()
	var count float64
	_ = metrics.New(reg, func() float64 { return count })

	check := func(want float64) {
		t.Helper()
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if mf.GetName() == "oidc_audit_events_dropped_total" {
				got := mf.GetMetric()[0].GetGauge().GetValue()
				if got != want {
					t.Errorf("Expected dropped=%v, got %v", want, got)
				}
				return
			}
		}
		t.Error("metric not found")
	}

	check(0)
	count = 5
	check(5)
	count = 12
	check(12)
}
