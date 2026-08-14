package security

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/syslog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// AuditLogger handles audit event logging
type AuditLogger struct {
	config        config.AuditConfig
	outputs       []AuditOutput
	eventChan     chan AuditEvent
	stopChan      chan struct{}
	wg            sync.WaitGroup
	droppedEvents atomic.Int64 // total events dropped due to full channel
	failedWrites  atomic.Int64 // total events that failed to write to an output (L-10)
	lastDropLog   atomic.Int64 // Unix second of last drop error log (rate limiter)
	// writeMu serializes all writes to outputs so that synchronous critical-event
	// writes (from any goroutine) don't race with the async processEvents goroutine.
	writeMu sync.Mutex
	// stopOnce makes Stop idempotent: it closes stopChan, and a second close
	// would panic. Callers that stop the logger on both a shutdown path and a
	// deferred cleanup are the normal case, not a mistake (#188).
	stopOnce sync.Once
}

// DroppedEvents returns the cumulative number of audit events dropped because
// the event channel was full and the overflow strategy is "drop" (the default).
func (al *AuditLogger) DroppedEvents() int64 {
	return al.droppedEvents.Load()
}

// FailedWrites returns the cumulative number of audit events that could not be
// written to an output (e.g. disk full, sink unreachable). Surfacing this lets
// operators alert on audit-pipeline failures rather than silently losing
// records (L-10).
func (al *AuditLogger) FailedWrites() int64 {
	return al.failedWrites.Load()
}

// AuditEvent represents a security audit event
type AuditEvent struct {
	Timestamp            time.Time              `json:"timestamp"`
	EventID              string                 `json:"event_id"`
	EventType            string                 `json:"event_type"`
	UserID               string                 `json:"user_id"`
	Email                string                 `json:"email"`
	Groups               []string               `json:"groups"`
	SourceIP             string                 `json:"source_ip"`
	UserAgent            string                 `json:"user_agent"`
	TargetHost           string                 `json:"target_host"`
	TargetResource       string                 `json:"target_resource"`
	SessionID            string                 `json:"session_id"`
	Provider             string                 `json:"provider"`
	AuthMethod           string                 `json:"auth_method"`
	MFAMethods           []string               `json:"mfa_methods"`
	Success              bool                   `json:"success"`
	ErrorMessage         string                 `json:"error_message"`
	ErrorCode            string                 `json:"error_code"`
	RiskScore            int                    `json:"risk_score"`
	RiskFactors          []string               `json:"risk_factors"`
	DeviceID             string                 `json:"device_id"`
	DeviceName           string                 `json:"device_name"`
	DeviceTrusted        bool                   `json:"device_trusted"`
	NetworkPath          []string               `json:"network_path"`
	TokenFingerprint     string                 `json:"token_fingerprint"`
	SSHKeyFingerprint    string                 `json:"ssh_key_fingerprint"`
	PolicyViolations     []string               `json:"policy_violations"`
	ComplianceFrameworks []string               `json:"compliance_frameworks"`
	DataClassification   string                 `json:"data_classification"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// AuditOutput represents an audit output destination
type AuditOutput interface {
	Write(event AuditEvent) error
	Close() error
}

// FileAuditOutput writes audit events to a file
type FileAuditOutput struct {
	file   *os.File
	config config.AuditOutput
}

// SyslogAuditOutput writes audit events to syslog
type SyslogAuditOutput struct {
	config config.AuditOutput
	writer *syslog.Writer
}

// HTTPAuditOutput writes audit events to an HTTP endpoint
type HTTPAuditOutput struct {
	config     config.AuditOutput
	httpClient *http.Client
}

const (
	httpAuditMaxRetries = 3
	httpAuditRetryDelay = time.Second
	httpAuditTimeout    = 10 * time.Second
)

// auditDrainBudget caps how long Stop spends writing the events still queued.
// It is a variable only so tests can shorten it; nothing outside this package
// sets it. Five seconds is chosen against the slowest output: one unreachable
// HTTP sink costs up to 33s for a single event, so the budget bounds shutdown at
// roughly one such event rather than the whole buffer.
var auditDrainBudget = 5 * time.Second

// NewAuditLogger creates a new audit logger
func NewAuditLogger(cfg config.AuditConfig) (*AuditLogger, error) {
	if !cfg.Enabled {
		return &AuditLogger{config: cfg}, nil
	}

	// (#170) Check every output before opening any of them, so a config naming
	// an output type that does not exist reports all of them at once instead of
	// failing on the first after the earlier ones are already on disk.
	if err := ValidateAuditConfig(cfg); err != nil {
		return nil, err
	}

	var outputs []AuditOutput

	// Create outputs
	for _, outputConfig := range cfg.Outputs {
		output, err := createAuditOutput(outputConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create audit output: %w", err)
		}
		outputs = append(outputs, output)
	}

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = 1000 // default async buffer
	}

	return &AuditLogger{
		config:    cfg,
		outputs:   outputs,
		eventChan: make(chan AuditEvent, bufSize),
		stopChan:  make(chan struct{}),
	}, nil
}

// Start starts the audit logger
func (al *AuditLogger) Start(ctx context.Context) error {
	if !al.config.Enabled {
		return nil
	}

	log.Info().Msg("Starting audit logger")

	// Start event processing goroutine
	al.wg.Add(1)
	go al.processEvents(ctx)

	return nil
}

// Stop stops the audit logger
func (al *AuditLogger) Stop() error {
	if !al.config.Enabled {
		return nil
	}

	al.stopOnce.Do(func() {
		log.Info().Msg("Stopping audit logger")

		// Stop event processing
		close(al.stopChan)
		al.wg.Wait()

		// The worker drains on its way out, but it may never have been started
		// (Stop without Start) or may already have returned on a cancelled
		// context, in which case what is queued is still unwritten. Draining
		// here as well makes "Stop returned" mean "every accepted event has
		// been written", which is what the rest of the code assumes.
		al.drain()

		// Close outputs
		for _, output := range al.outputs {
			if err := output.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close audit output")
			}
		}
	})

	return nil
}

// drain writes the events already queued when the logger was told to stop.
//
// Without this, Stop discarded them: processEvents selected on stopChan and
// returned, and everything still buffered in eventChan went to the garbage
// collector unwritten (#188). The events most likely to be sitting in that
// buffer are the ones logged immediately before shutdown — the tail of the
// audit trail, and the part an investigation into why a host went down would
// want. Losing records quietly is the one behaviour an audit trail may not
// have, which is also why the default overflow strategy is "block".
//
// Draining is bounded twice over. By the buffer, because LogAuthEvent's callers
// have stopped by the time Stop is called, so no new events arrive and the
// default branch ends the loop as soon as the buffer is empty. And by
// auditDrainBudget, because an output can be arbitrarily slow: an unreachable
// HTTP sink costs up to httpAuditMaxRetries timeouts plus backoff per event, so
// draining a full 1000-event buffer into one could hold shutdown for hours. A
// shutdown that does not finish is worse than a lost record, so the budget wins
// and what it abandons is counted and logged rather than silently forgotten.
func (al *AuditLogger) drain() {
	deadline := time.Now().Add(auditDrainBudget)
	for {
		select {
		case event := <-al.eventChan:
			al.writeMu.Lock()
			al.writeEvent(event)
			al.writeMu.Unlock()
			// Checked after a write, so the budget can never stop the drain
			// before it has made progress.
			if time.Now().After(deadline) {
				al.abandonQueue()
				return
			}
		default:
			return
		}
	}
}

// abandonQueue accounts for the events the drain budget left unwritten, so
// DroppedEvents and the shutdown log tell an operator that the end of the audit
// trail is incomplete. A gap nobody is told about is indistinguishable from
// nothing having happened.
func (al *AuditLogger) abandonQueue() {
	remaining := len(al.eventChan)
	if remaining == 0 {
		return
	}
	total := al.droppedEvents.Add(int64(remaining))
	log.Error().
		Int("abandoned", remaining).
		Int64("total_dropped", total).
		Dur("budget", auditDrainBudget).
		Msg("Audit drain budget exhausted at shutdown; queued events were not written")
}

// LogAuthEvent logs an authentication event
func (al *AuditLogger) LogAuthEvent(event AuditEvent) {
	if !al.config.Enabled {
		return
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Generate event ID if not provided
	if event.EventID == "" {
		event.EventID = generateEventID()
	}

	// Add compliance frameworks
	if len(al.config.ComplianceFrameworks) > 0 {
		event.ComplianceFrameworks = al.config.ComplianceFrameworks
	}

	// Critical events are always written synchronously to preserve audit trail integrity.
	if isCriticalEvent(event) {
		al.writeEventSync(event)
		return
	}

	// Non-critical events are dispatched according to the configured overflow
	// strategy. The default (unset) is "block" so audit records are not silently
	// lost under load (L-9); operators must explicitly opt into "drop".
	switch al.config.OverflowStrategy {
	case "", "block":
		// Apply backpressure: block the caller until the channel has room.
		al.eventChan <- event
	case "sync":
		// Bypass the async channel and write directly, serialised by writeMu so
		// concurrent callers do not interleave partial writes.
		al.writeEventSync(event)
	default: // "drop" (explicitly configured) or any unrecognised value
		select {
		case al.eventChan <- event:
		default:
			dropped := al.droppedEvents.Add(1)
			// Rate-limit the error log to at most once per second to avoid
			// flooding the log when the channel is persistently full.
			now := time.Now().Unix()
			last := al.lastDropLog.Load()
			if now > last && al.lastDropLog.CompareAndSwap(last, now) {
				log.Error().
					Int64("total_dropped", dropped).
					Msg("Audit event channel full — events are being dropped")
			}
		}
	}
}

// LogEvent logs a generic audit event
func (al *AuditLogger) LogEvent(event AuditEvent) {
	al.LogAuthEvent(event)
}

// processEvents processes audit events asynchronously
func (al *AuditLogger) processEvents(ctx context.Context) {
	defer al.wg.Done()

	for {
		select {
		case <-ctx.Done():
			al.drain()
			return
		case <-al.stopChan:
			al.drain()
			return
		case event := <-al.eventChan:
			al.writeMu.Lock()
			al.writeEvent(event)
			al.writeMu.Unlock()
		}
	}
}

// writeEvent writes an event to all configured outputs.
// Callers must hold writeMu.
func (al *AuditLogger) writeEvent(event AuditEvent) {
	for _, output := range al.outputs {
		if err := output.Write(event); err != nil {
			al.failedWrites.Add(1)
			log.Error().
				Err(err).
				Str("event_type", event.EventType).
				Str("event_id", event.EventID).
				Int64("total_failed_writes", al.failedWrites.Load()).
				Msg("Failed to write audit event")
		}
	}
}

// writeEventSync writes a critical event synchronously to all outputs, bypassing
// the async channel. Safe to call from any goroutine.
func (al *AuditLogger) writeEventSync(event AuditEvent) {
	al.writeMu.Lock()
	defer al.writeMu.Unlock()
	al.writeEvent(event)
}

// isCriticalEvent returns true for events that must never be dropped.
// These are written synchronously rather than through the async channel.
func isCriticalEvent(event AuditEvent) bool {
	switch event.EventType {
	case "authentication_successful", "session_revoked", "token_refresh_failed",
		"device_authorization_failed":
		return true
	}
	// Any security rejection is critical regardless of event type.
	return !event.Success && event.ErrorCode != ""
}

// Helper functions

// auditOutputConstructors is the set of audit output types that exist. Both
// createAuditOutput and ValidateAuditConfig read it, so what the broker accepts
// and what a configuration check reports can never drift apart (#170).
var auditOutputConstructors = map[string]func(config.AuditOutput) (AuditOutput, error){
	"file":   func(c config.AuditOutput) (AuditOutput, error) { return NewFileAuditOutput(c) },
	"stdout": func(c config.AuditOutput) (AuditOutput, error) { return NewStdoutAuditOutput(c) },
	"syslog": func(c config.AuditOutput) (AuditOutput, error) { return NewSyslogAuditOutput(c) },
	"http":   func(c config.AuditOutput) (AuditOutput, error) { return NewHTTPAuditOutput(c) },
}

func createAuditOutput(config config.AuditOutput) (AuditOutput, error) {
	newOutput, ok := auditOutputConstructors[config.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported audit output type %q (supported: %s)", config.Type, SupportedAuditOutputTypes())
	}
	return newOutput(config)
}

// SupportedAuditOutputTypes lists the values audit.outputs[].type accepts,
// sorted, for use in error messages and documentation.
func SupportedAuditOutputTypes() string {
	types := make([]string, 0, len(auditOutputConstructors))
	for t := range auditOutputConstructors {
		types = append(types, t)
	}
	sort.Strings(types)
	return strings.Join(types, ", ")
}

// ValidateAuditConfig reports everything wrong with an audit configuration
// without opening a file, connecting to syslog or reaching the network, so a
// configuration can be checked by a test running as an ordinary user (#170).
//
// configs/production/broker-enterprise.yaml — recommended as a template by
// CONFIGURATION-GUIDE.md — named the output types "remote_syslog" and "webhook",
// neither of which exists. createAuditOutput's error reaches log.Fatal in
// cmd/broker, so that file was fatal at startup for as long as it has shipped.
func ValidateAuditConfig(cfg config.AuditConfig) error {
	if !cfg.Enabled {
		return nil
	}

	var problems []string

	// (#210) audit.enabled defaults to true and audit.outputs has no default, so a
	// configuration that omits the audit block entirely — or writes
	// `audit: {enabled: true}` — used to produce a logger with no destinations.
	// writeEvent then iterated an empty slice: every event was accepted, nothing
	// was written, and neither DroppedEvents nor FailedWrites moved, so the two
	// counters an operator alerts on stayed at zero while the audit trail did not
	// exist. Refusing to start is the only honest answer. Defaulting to stdout
	// would be worse: it puts the audit trail somewhere the operator did not
	// choose (the journal, under the shipped unit) and keeps the "auditing is on"
	// claim true by moving the records rather than by writing them where asked.
	if len(cfg.Outputs) == 0 {
		problems = append(problems, "audit.enabled is true but audit.outputs is empty: "+
			"name at least one output ("+SupportedAuditOutputTypes()+"), or set audit.enabled: false")
	}

	for i, out := range cfg.Outputs {
		if _, ok := auditOutputConstructors[out.Type]; !ok {
			problems = append(problems, fmt.Sprintf("audit.outputs[%d]: unsupported type %q (supported: %s)",
				i, out.Type, SupportedAuditOutputTypes()))
			continue
		}
		switch out.Type {
		case "file":
			if out.Path == "" {
				problems = append(problems, fmt.Sprintf("audit.outputs[%d] (file): path is required", i))
			}
		case "http":
			if out.URL == "" {
				problems = append(problems, fmt.Sprintf("audit.outputs[%d] (http): url is required", i))
			}
		}
	}

	// An unrecognised strategy falls through to "drop" in writeAuditEvent, which
	// discards records under load — the one behaviour an operator has to opt into
	// explicitly. A typo must not choose it.
	switch cfg.OverflowStrategy {
	case "", "block", "sync", "drop":
	default:
		problems = append(problems, fmt.Sprintf("audit.overflow_strategy %q is not one of block, sync, drop",
			cfg.OverflowStrategy))
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid audit configuration: %s", strings.Join(problems, "; "))
	}
	return nil
}

func generateEventID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// This indicates a broken system; return a best-effort fallback.
		return fmt.Sprintf("audit_%d", time.Now().UnixNano())
	}
	return "audit_" + hex.EncodeToString(b)
}

// FileAuditOutput implementation

func NewFileAuditOutput(config config.AuditOutput) (*FileAuditOutput, error) {
	file, err := os.OpenFile(config.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit file: %w", err)
	}

	return &FileAuditOutput{
		file:   file,
		config: config,
	}, nil
}

func (fao *FileAuditOutput) Write(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	_, err = fao.file.Write(append(data, '\n'))
	if err != nil {
		return fmt.Errorf("failed to write audit event to file: %w", err)
	}

	return fao.file.Sync()
}

func (fao *FileAuditOutput) Close() error {
	return fao.file.Close()
}

// StdoutAuditOutput writes audit events to stdout
type StdoutAuditOutput struct {
	config config.AuditOutput
}

func NewStdoutAuditOutput(config config.AuditOutput) (*StdoutAuditOutput, error) {
	return &StdoutAuditOutput{
		config: config,
	}, nil
}

func (sao *StdoutAuditOutput) Write(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func (sao *StdoutAuditOutput) Close() error {
	return nil
}

// SyslogAuditOutput implementation

func NewSyslogAuditOutput(cfg config.AuditOutput) (*SyslogAuditOutput, error) {
	priority := parseSyslogPriority(cfg.Facility, cfg.Severity)
	writer, err := syslog.New(priority, "oidc-pam")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog: %w", err)
	}
	return &SyslogAuditOutput{config: cfg, writer: writer}, nil
}

func (sao *SyslogAuditOutput) Write(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}
	msg := string(data)

	switch strings.ToUpper(sao.config.Severity) {
	case "EMERG", "EMERGENCY":
		return sao.writer.Emerg(msg)
	case "ALERT":
		return sao.writer.Alert(msg)
	case "CRIT", "CRITICAL":
		return sao.writer.Crit(msg)
	case "ERR", "ERROR":
		return sao.writer.Err(msg)
	case "WARNING", "WARN":
		return sao.writer.Warning(msg)
	case "NOTICE":
		return sao.writer.Notice(msg)
	case "DEBUG":
		return sao.writer.Debug(msg)
	default: // INFO
		return sao.writer.Info(msg)
	}
}

func (sao *SyslogAuditOutput) Close() error {
	return sao.writer.Close()
}

// parseSyslogPriority maps facility/severity strings to a syslog.Priority value.
func parseSyslogPriority(facility, severity string) syslog.Priority {
	return parseSyslogFacility(facility) | parseSyslogSeverity(severity)
}

func parseSyslogFacility(facility string) syslog.Priority {
	switch strings.ToUpper(facility) {
	case "KERN":
		return syslog.LOG_KERN
	case "USER":
		return syslog.LOG_USER
	case "MAIL":
		return syslog.LOG_MAIL
	case "DAEMON":
		return syslog.LOG_DAEMON
	case "AUTH", "SECURITY":
		return syslog.LOG_AUTH
	case "SYSLOG":
		return syslog.LOG_SYSLOG
	case "LPR":
		return syslog.LOG_LPR
	case "NEWS":
		return syslog.LOG_NEWS
	case "UUCP":
		return syslog.LOG_UUCP
	case "CRON":
		return syslog.LOG_CRON
	case "AUTHPRIV":
		return syslog.LOG_AUTHPRIV
	case "FTP":
		return syslog.LOG_FTP
	case "LOCAL0":
		return syslog.LOG_LOCAL0
	case "LOCAL1":
		return syslog.LOG_LOCAL1
	case "LOCAL2":
		return syslog.LOG_LOCAL2
	case "LOCAL3":
		return syslog.LOG_LOCAL3
	case "LOCAL4":
		return syslog.LOG_LOCAL4
	case "LOCAL5":
		return syslog.LOG_LOCAL5
	case "LOCAL6":
		return syslog.LOG_LOCAL6
	case "LOCAL7":
		return syslog.LOG_LOCAL7
	default:
		return syslog.LOG_AUTHPRIV // sensible default for auth-related events
	}
}

func parseSyslogSeverity(severity string) syslog.Priority {
	switch strings.ToUpper(severity) {
	case "EMERG", "EMERGENCY":
		return syslog.LOG_EMERG
	case "ALERT":
		return syslog.LOG_ALERT
	case "CRIT", "CRITICAL":
		return syslog.LOG_CRIT
	case "ERR", "ERROR":
		return syslog.LOG_ERR
	case "WARNING", "WARN":
		return syslog.LOG_WARNING
	case "NOTICE":
		return syslog.LOG_NOTICE
	case "DEBUG":
		return syslog.LOG_DEBUG
	default: // INFO
		return syslog.LOG_INFO
	}
}

// HTTPAuditOutput implementation

func NewHTTPAuditOutput(cfg config.AuditOutput) (*HTTPAuditOutput, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("HTTP audit output requires a non-empty URL")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &HTTPAuditOutput{
		config: cfg,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   httpAuditTimeout,
		},
	}, nil
}

func (hao *HTTPAuditOutput) Write(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < httpAuditMaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * httpAuditRetryDelay)
		}

		req, err := http.NewRequest(http.MethodPost, hao.config.URL, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("failed to create HTTP audit request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hao.config.Headers {
			req.Header.Set(k, v)
		}

		resp, err := hao.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("HTTP audit POST failed: %w", err)
			log.Warn().Err(lastErr).Int("attempt", attempt+1).Str("url", hao.config.URL).
				Msg("Audit HTTP POST failed, retrying")
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		lastErr = fmt.Errorf("audit HTTP endpoint returned status %d", resp.StatusCode)
		log.Warn().Err(lastErr).Int("attempt", attempt+1).Str("url", hao.config.URL).
			Msg("Audit HTTP POST returned non-2xx, retrying")
	}

	return fmt.Errorf("audit HTTP POST failed after %d attempts: %w", httpAuditMaxRetries, lastErr)
}

func (hao *HTTPAuditOutput) Close() error {
	hao.httpClient.CloseIdleConnections()
	return nil
}
