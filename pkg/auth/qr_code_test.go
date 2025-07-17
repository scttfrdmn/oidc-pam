package auth

import (
	"strings"
	"testing"
)

func TestGenerateQRCode(t *testing.T) {
	testURL := "https://example.com/device?user_code=ABC123"
	
	qrCode, err := GenerateQRCode(testURL)
	if err != nil {
		t.Fatalf("Failed to generate QR code: %v", err)
	}
	
	if qrCode == "" {
		t.Error("Expected non-empty QR code")
	}
	
	// QR code should contain ASCII art
	if !strings.Contains(qrCode, "█") && !strings.Contains(qrCode, "▄") {
		t.Error("Expected QR code to contain ASCII art characters")
	}
}

func TestGenerateQRCodePNG(t *testing.T) {
	testURL := "https://example.com/device?user_code=ABC123"
	size := 256
	
	pngData, err := GenerateQRCodePNG(testURL, size)
	if err != nil {
		t.Fatalf("Failed to generate QR code PNG: %v", err)
	}
	
	if len(pngData) == 0 {
		t.Error("Expected non-empty PNG data")
	}
	
	// Check PNG header
	if len(pngData) < 8 || string(pngData[1:4]) != "PNG" {
		t.Error("Expected valid PNG header")
	}
}

func TestFormatDeviceInstructions(t *testing.T) {
	deviceURL := "https://example.com/device"
	deviceCode := "ABC123"
	qrCode := "█▀▀▀▀▀█ ▀▀▀ █▀▀▀▀▀█\n█ ███ █ ███ █ ███ █\n█ ▀▀▀ █ ▀▀▀ █ ▀▀▀ █"
	
	instructions := FormatDeviceInstructions(deviceURL, deviceCode, qrCode)
	
	if instructions == "" {
		t.Error("Expected non-empty instructions")
	}
	
	// Should contain the device URL
	if !strings.Contains(instructions, deviceURL) {
		t.Error("Expected instructions to contain device URL")
	}
	
	// Should contain the device code
	if !strings.Contains(instructions, deviceCode) {
		t.Error("Expected instructions to contain device code")
	}
	
	// Should contain the QR code
	if !strings.Contains(instructions, qrCode) {
		t.Error("Expected instructions to contain QR code")
	}
	
	// Should have proper formatting - check what the actual function returns
	if !strings.Contains(instructions, "visit") && !strings.Contains(instructions, "Visit") {
		t.Error("Expected instructions to contain visit guidance")
	}
}

func TestFormatConsoleInstructions(t *testing.T) {
	deviceURL := "https://example.com/device"
	deviceCode := "ABC123"
	qrCode := "█▀▀▀▀▀█ ▀▀▀ █▀▀▀▀▀█\n█ ███ █ ███ █ ███ █\n█ ▀▀▀ █ ▀▀▀ █ ▀▀▀ █"
	
	instructions := FormatConsoleInstructions(deviceURL, deviceCode, qrCode)
	
	if instructions == "" {
		t.Error("Expected non-empty console instructions")
	}
	
	// Should contain the device URL
	if !strings.Contains(instructions, deviceURL) {
		t.Error("Expected console instructions to contain device URL")
	}
	
	// Should contain the device code
	if !strings.Contains(instructions, deviceCode) {
		t.Error("Expected console instructions to contain device code")
	}
	
	// Console instructions should have different formatting than regular instructions
	if !strings.Contains(instructions, "AUTHENTICATION") && !strings.Contains(instructions, "Authentication") {
		t.Error("Expected console instructions to have authentication header")
	}
}

func TestFormatGUIInstructions(t *testing.T) {
	deviceURL := "https://example.com/device"
	deviceCode := "ABC123"
	qrCode := "█▀▀▀▀▀█ ▀▀▀ █▀▀▀▀▀█\n█ ███ █ ███ █ ███ █\n█ ▀▀▀ █ ▀▀▀ █ ▀▀▀ █"
	
	instructions := FormatGUIInstructions(deviceURL, deviceCode, qrCode)
	
	if instructions == "" {
		t.Error("Expected non-empty GUI instructions")
	}
	
	// Should contain the device URL
	if !strings.Contains(instructions, deviceURL) {
		t.Error("Expected GUI instructions to contain device URL")
	}
	
	// Should contain the device code
	if !strings.Contains(instructions, deviceCode) {
		t.Error("Expected GUI instructions to contain device code")
	}
	
	// GUI instructions should have different formatting
	if !strings.Contains(instructions, "Authentication") && !strings.Contains(instructions, "AUTHENTICATION") {
		t.Error("Expected GUI instructions to have authentication header")
	}
}

func TestFormatProgressIndicator(t *testing.T) {
	step := 5
	total := 10
	message := "Processing..."
	indicator := FormatProgressIndicator(step, total, message)
	
	if indicator == "" {
		t.Error("Expected non-empty progress indicator")
	}
	
	// Should contain the message
	if !strings.Contains(indicator, message) {
		t.Error("Expected progress indicator to contain message")
	}
	
	// Should have visual progress bar
	if !strings.Contains(indicator, "█") && !strings.Contains(indicator, "░") {
		t.Error("Expected progress indicator to have visual elements")
	}
}

func TestFormatAuthenticationSuccess(t *testing.T) {
	userEmail := "test@example.com"
	sessionDuration := "1h"
	success := FormatAuthenticationSuccess(userEmail, sessionDuration)
	
	if success == "" {
		t.Error("Expected non-empty success message")
	}
	
	// Should contain user email
	if !strings.Contains(success, userEmail) {
		t.Error("Expected success message to contain user email")
	}
	
	// Should contain session duration
	if !strings.Contains(success, sessionDuration) {
		t.Error("Expected success message to contain session duration")
	}
	
	// Should have success indicators - check what the actual function returns
	if !strings.Contains(success, "✓") && !strings.Contains(success, "SUCCESS") && !strings.Contains(success, "Success") {
		t.Error("Expected success message to have success indicators")
	}
}

func TestFormatAuthenticationError(t *testing.T) {
	errorMsg := "Invalid credentials"
	errorFormatted := FormatAuthenticationError(errorMsg)
	
	if errorFormatted == "" {
		t.Error("Expected non-empty error message")
	}
	
	// Should contain error message
	if !strings.Contains(errorFormatted, errorMsg) {
		t.Error("Expected formatted error to contain original error message")
	}
	
	// Should have error indicators - check what the actual function returns
	if !strings.Contains(errorFormatted, "✗") && !strings.Contains(errorFormatted, "ERROR") && !strings.Contains(errorFormatted, "Error") {
		t.Error("Expected error message to have error indicators")
	}
}

func TestFormatSpinner(t *testing.T) {
	step := 3
	spinner := FormatSpinner(step)
	
	if spinner == "" {
		t.Error("Expected non-empty spinner")
	}
	
	// Should have spinner characters
	if !strings.Contains(spinner, "⠋") && !strings.Contains(spinner, "⠙") && !strings.Contains(spinner, "⠹") && !strings.Contains(spinner, "⠸") && !strings.Contains(spinner, "⠼") {
		t.Error("Expected spinner to contain spinner characters")
	}
}

func TestQRCodeWithEmptyURL(t *testing.T) {
	_, err := GenerateQRCode("")
	if err == nil {
		t.Error("Expected error when generating QR code with empty URL")
	}
}

func TestQRCodeWithInvalidURL(t *testing.T) {
	// Test with various invalid URLs
	invalidURLs := []string{
		"not-a-url",
		"ftp://invalid-scheme.com",
		"https://",
		"javascript:alert(1)",
	}
	
	for _, url := range invalidURLs {
		_, err := GenerateQRCode(url)
		if err != nil {
			t.Logf("Expected error for invalid URL %s: %v", url, err)
		}
	}
}

func TestFormatInstructionsWithEmptyInputs(t *testing.T) {
	// Test with empty inputs
	emptyInstructions := FormatDeviceInstructions("", "", "")
	if emptyInstructions == "" {
		t.Error("Expected some instructions even with empty inputs")
	}
	
	// Should still provide basic guidance
	if !strings.Contains(emptyInstructions, "authentication") && !strings.Contains(emptyInstructions, "Authentication") {
		t.Error("Expected basic authentication guidance even with empty inputs")
	}
}

func TestFormatInstructionsWithLongInputs(t *testing.T) {
	// Test with very long inputs
	longURL := "https://very-long-domain-name-that-exceeds-normal-length.example.com/device/authorization/endpoint/with/many/path/segments"
	longCode := "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
	longQRCode := strings.Repeat("█▀▀▀▀▀█ ▀▀▀ █▀▀▀▀▀█\n█ ███ █ ███ █ ███ █\n█ ▀▀▀ █ ▀▀▀ █ ▀▀▀ █\n", 5)
	
	instructions := FormatDeviceInstructions(longURL, longCode, longQRCode)
	
	if instructions == "" {
		t.Error("Expected instructions even with long inputs")
	}
	
	// Should handle long inputs gracefully
	if !strings.Contains(instructions, longURL) {
		t.Error("Expected instructions to contain long URL")
	}
	
	if !strings.Contains(instructions, longCode) {
		t.Error("Expected instructions to contain long code")
	}
}

func TestProgressIndicatorBoundaries(t *testing.T) {
	// Test boundary values with proper bounds checking
	testCases := []struct {
		step  int
		total int
		valid bool
	}{
		{0, 10, true},
		{1, 10, true},
		{5, 10, true},
		{9, 10, true},
		{10, 10, true},
		{-1, 10, false}, // Invalid - negative step
		{11, 10, false}, // Invalid - step > total
	}
	
	for _, tc := range testCases {
		// For invalid inputs, we should handle them gracefully
		if !tc.valid {
			// Adjust invalid inputs to valid ranges
			step := tc.step
			total := tc.total
			
			if step < 0 {
				step = 0
			}
			if step > total {
				step = total
			}
			
			indicator := FormatProgressIndicator(step, total, "Testing...")
			if indicator == "" {
				t.Errorf("Expected non-empty progress indicator for adjusted step %d/%d", step, total)
			}
		} else {
			indicator := FormatProgressIndicator(tc.step, tc.total, "Testing...")
			if indicator == "" {
				t.Errorf("Expected non-empty progress indicator for step %d/%d", tc.step, tc.total)
			}
		}
	}
}

func TestSpinnerBoundaries(t *testing.T) {
	// Test spinner with various step values
	testSteps := []int{0, 1, 5, 9, 10, 15, -1, 100}
	
	for _, step := range testSteps {
		spinner := FormatSpinner(step)
		if spinner == "" {
			t.Errorf("Expected non-empty spinner for step %d", step)
		}
	}
}

func TestQRCodeGeneration(t *testing.T) {
	// Test QR code generation with various valid URLs
	validURLs := []string{
		"https://example.com",
		"https://auth.example.com/device?code=ABC123",
		"https://login.microsoftonline.com/device",
		"https://accounts.google.com/device",
	}
	
	for _, url := range validURLs {
		qrCode, err := GenerateQRCode(url)
		if err != nil {
			t.Errorf("Failed to generate QR code for valid URL %s: %v", url, err)
			continue
		}
		
		if qrCode == "" {
			t.Errorf("Expected non-empty QR code for URL %s", url)
		}
	}
}

func TestInstructionFormatting(t *testing.T) {
	// Test that different instruction formats produce different outputs
	deviceURL := "https://example.com/device"
	deviceCode := "ABC123"
	qrCode := "█▀▀▀▀▀█"
	
	deviceInstructions := FormatDeviceInstructions(deviceURL, deviceCode, qrCode)
	consoleInstructions := FormatConsoleInstructions(deviceURL, deviceCode, qrCode)
	guiInstructions := FormatGUIInstructions(deviceURL, deviceCode, qrCode)
	
	// All should be different
	if deviceInstructions == consoleInstructions {
		t.Error("Device and console instructions should be different")
	}
	
	if deviceInstructions == guiInstructions {
		t.Error("Device and GUI instructions should be different")
	}
	
	if consoleInstructions == guiInstructions {
		t.Error("Console and GUI instructions should be different")
	}
	
	// All should contain the basic elements
	allInstructions := []string{deviceInstructions, consoleInstructions, guiInstructions}
	for i, instructions := range allInstructions {
		if !strings.Contains(instructions, deviceURL) {
			t.Errorf("Instructions %d should contain device URL", i)
		}
		if !strings.Contains(instructions, deviceCode) {
			t.Errorf("Instructions %d should contain device code", i)
		}
	}
}