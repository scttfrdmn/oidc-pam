package security

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// AuditLogger handles audit event logging
type AuditLogger struct {
	config   config.AuditConfig
	outputs  []AuditOutput
	eventChan chan AuditEvent
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// AuditEvent represents a security audit event
type AuditEvent struct {
	Timestamp    time.Time              `json:"timestamp"`
	EventID      string                 `json:"event_id"`
	EventType    string                 `json:"event_type"`
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email"`
	Groups       []string               `json:"groups"`
	SourceIP     string                 `json:"source_ip"`
	UserAgent    string                 `json:"user_agent"`
	TargetHost   string                 `json:"target_host"`
	TargetResource string               `json:"target_resource"`
	SessionID    string                 `json:"session_id"`
	Provider     string                 `json:"provider"`
	AuthMethod   string                 `json:"auth_method"`
	MFAMethods   []string               `json:"mfa_methods"`
	Success      bool                   `json:"success"`
	ErrorMessage string                 `json:"error_message"`
	ErrorCode    string                 `json:"error_code"`
	RiskScore    int                    `json:"risk_score"`
	RiskFactors  []string               `json:"risk_factors"`
	DeviceID     string                 `json:"device_id"`
	DeviceName   string                 `json:"device_name"`
	DeviceTrusted bool                  `json:"device_trusted"`
	NetworkPath  []string               `json:"network_path"`
	TokenFingerprint string             `json:"token_fingerprint"`
	SSHKeyFingerprint string            `json:"ssh_key_fingerprint"`
	PolicyViolations []string            `json:"policy_violations"`
	ComplianceFrameworks []string        `json:"compliance_frameworks"`
	DataClassification string            `json:"data_classification"`
	Metadata     map[string]interface{} `json:"metadata"`
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
}

// HTTPAuditOutput writes audit events to an HTTP endpoint
type HTTPAuditOutput struct {
	config config.AuditOutput
}

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

	return &AuditLogger{
		config:    cfg,
		outputs:   outputs,
		eventChan: make(chan AuditEvent, 1000), // Buffer for async processing
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

	// Send to event channel for async processing
	select {
	case al.eventChan <- event:
	default:
		log.Warn().Msg("Audit event channel full, dropping event")
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
	return fmt.Sprintf("audit_%d", time.Now().UnixNano())
}

// FileAuditOutput implementation

func NewFileAuditOutput(config config.AuditOutput) (*FileAuditOutput, error) {
	file, err := os.OpenFile(config.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

func NewSyslogAuditOutput(config config.AuditOutput) (*SyslogAuditOutput, error) {
	// This would implement syslog output
	// For now, return a placeholder
	return &SyslogAuditOutput{
		config: config,
	}, nil
}

func (sao *SyslogAuditOutput) Write(event AuditEvent) error {
	// This would write to syslog
	// For now, just log to stderr
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	log.Info().
		Str("facility", sao.config.Facility).
		Str("severity", sao.config.Severity).
		RawJSON("event", data).
		Msg("Syslog audit event")

	return nil
}

func (sao *SyslogAuditOutput) Close() error {
	return nil
}

// HTTPAuditOutput implementation

func NewHTTPAuditOutput(config config.AuditOutput) (*HTTPAuditOutput, error) {
	// This would implement HTTP output
	// For now, return a placeholder
	return &HTTPAuditOutput{
		config: config,
	}, nil
}

func (hao *HTTPAuditOutput) Write(event AuditEvent) error {
	// This would POST to an HTTP endpoint
	// For now, just log
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	log.Info().
		Str("url", hao.config.URL).
		RawJSON("event", data).
		Msg("HTTP audit event")

	return nil
}

func (hao *HTTPAuditOutput) Close() error {
	return nil
}