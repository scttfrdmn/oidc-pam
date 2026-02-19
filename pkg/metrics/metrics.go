// Package metrics defines and registers Prometheus instruments for the
// OIDC-PAM broker.  Callers obtain a *Metrics via New() and pass it to the
// broker / policy engine via their respective SetMetrics methods.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds every Prometheus instrument used by the broker.
type Metrics struct {
	// AuthAttempts counts completed authentication attempts.
	// Labels: provider, result (success|failure|policy_denied), error_code.
	AuthAttempts *prometheus.CounterVec

	// ActiveSessions is the number of currently active (IsActive=true) sessions.
	ActiveSessions prometheus.Gauge

	// PolicyEvaluations counts policy evaluation outcomes.
	// Labels: result (allowed|denied).
	PolicyEvaluations *prometheus.CounterVec

	// RiskScore observes per-request risk scores (0–100).
	RiskScore prometheus.Histogram

	// SSHKeyOperations counts generate/revoke operations.
	// Labels: operation (generate|revoke), result (success|failure).
	SSHKeyOperations *prometheus.CounterVec
}

// New creates and registers all metrics with reg.  If droppedEventsFn is
// non-nil it is used to back an oidc_audit_events_dropped gauge so operators
// can track events dropped by the audit subsystem.
func New(reg prometheus.Registerer, droppedEventsFn func() float64) *Metrics {
	authAttempts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "oidc_auth_attempts_total",
		Help: "Total authentication attempts by provider, result and error code.",
	}, []string{"provider", "result", "error_code"})

	activeSessions := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "oidc_active_sessions",
		Help: "Number of currently active authentication sessions.",
	})

	policyEvaluations := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "oidc_policy_evaluations_total",
		Help: "Total policy evaluations by result (allowed or denied).",
	}, []string{"result"})

	riskScore := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "oidc_risk_score",
		Help:    "Distribution of risk scores assigned during policy evaluation.",
		Buckets: []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
	})

	sshKeyOperations := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "oidc_ssh_key_operations_total",
		Help: "Total SSH key generate/revoke operations by operation and result.",
	}, []string{"operation", "result"})

	reg.MustRegister(authAttempts, activeSessions, policyEvaluations, riskScore, sshKeyOperations)

	if droppedEventsFn != nil {
		droppedGauge := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "oidc_audit_events_dropped_total",
			Help: "Cumulative audit events dropped because the event channel was full.",
		}, droppedEventsFn)
		reg.MustRegister(droppedGauge)
	}

	return &Metrics{
		AuthAttempts:      authAttempts,
		ActiveSessions:    activeSessions,
		PolicyEvaluations: policyEvaluations,
		RiskScore:         riskScore,
		SSHKeyOperations:  sshKeyOperations,
	}
}

// RecordAuth is a convenience wrapper that increments AuthAttempts.
func (m *Metrics) RecordAuth(provider, result, errorCode string) {
	m.AuthAttempts.WithLabelValues(provider, result, errorCode).Inc()
}

// RecordPolicyEval increments PolicyEvaluations and observes the risk score.
func (m *Metrics) RecordPolicyEval(allowed bool, riskScore int) {
	result := "denied"
	if allowed {
		result = "allowed"
	}
	m.PolicyEvaluations.WithLabelValues(result).Inc()
	m.RiskScore.Observe(float64(riskScore))
}

// RecordSSHKeyOp increments SSHKeyOperations.
func (m *Metrics) RecordSSHKeyOp(operation, result string) {
	m.SSHKeyOperations.WithLabelValues(operation, result).Inc()
}
