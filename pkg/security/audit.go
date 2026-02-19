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
	lastDropLog   atomic.Int64 // Unix second of last drop error log (rate limiter)
	syncMu        sync.Mutex   // serialises direct writeEvent calls for "sync" strategy
}

// DroppedEvents returns the cumulative number of audit events dropped because
// the event channel was full and the overflow strategy is "drop" (the default).
func (al *AuditLogger) DroppedEvents() int64 {
	return al.droppedEvents.Load()
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

// NewAuditLogger creates a new audit logger
func NewAuditLogger(cfg config.AuditConfig) (*AuditLogger, error) {
	if !cfg.Enabled {
		return &AuditLogger{config: cfg}, nil
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

	log.Info().Msg("Stopping audit logger")

	// Stop event processing
	close(al.stopChan)
	al.wg.Wait()

	// Close outputs
	for _, output := range al.outputs {
		if err := output.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close audit output")
		}
	}

	return nil
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

	// Dispatch according to the configured overflow strategy.
	switch al.config.OverflowStrategy {
	case "block":
		// Apply backpressure: block the caller until the channel has room.
		al.eventChan <- event
	case "sync":
		// Bypass the async channel and write directly, serialised by syncMu so
		// concurrent callers do not interleave partial writes.
		al.syncMu.Lock()
		al.writeEvent(event)
		al.syncMu.Unlock()
	default: // "drop" (and any unrecognised value)
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
			return
		case <-al.stopChan:
			return
		case event := <-al.eventChan:
			al.writeEvent(event)
		}
	}
}

// writeEvent writes an event to all configured outputs
func (al *AuditLogger) writeEvent(event AuditEvent) {
	for _, output := range al.outputs {
		if err := output.Write(event); err != nil {
			log.Error().
				Err(err).
				Str("event_type", event.EventType).
				Str("event_id", event.EventID).
				Msg("Failed to write audit event")
		}
	}
}

// Helper functions

func createAuditOutput(config config.AuditOutput) (AuditOutput, error) {
	switch config.Type {
	case "file":
		return NewFileAuditOutput(config)
	case "stdout":
		return NewStdoutAuditOutput(config)
	case "syslog":
		return NewSyslogAuditOutput(config)
	case "http":
		return NewHTTPAuditOutput(config)
	default:
		return nil, fmt.Errorf("unsupported audit output type: %s", config.Type)
	}
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
		resp.Body.Close()

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
