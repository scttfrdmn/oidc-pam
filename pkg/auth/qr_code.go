package auth

import (
	"fmt"
	"strings"

	"github.com/skip2/go-qrcode"
)

// GenerateQRCode generates a QR code for the given URL
func GenerateQRCode(url string) (string, error) {
	// Generate QR code
	qr, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Convert to ASCII art for terminal display
	return qr.ToSmallString(false), nil
}

// GenerateQRCodePNG generates a QR code as PNG data
func GenerateQRCodePNG(url string, size int) ([]byte, error) {
	return qrcode.Encode(url, qrcode.Medium, size)
}

// FormatDeviceInstructions formats instructions for device flow authentication
func FormatDeviceInstructions(deviceURL, userCode, qrCode string) string {
	var instructions strings.Builder

	instructions.WriteString("🔐 OIDC Authentication Required\n")
	instructions.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	if qrCode != "" {
		instructions.WriteString("📱 Option 1: Scan QR code with your mobile device\n")
		instructions.WriteString(qrCode)
		instructions.WriteString("\n")
	}

	instructions.WriteString("📱 Option 2: Visit the following URL on your mobile device:\n")
	instructions.WriteString(fmt.Sprintf("🔗 %s\n\n", deviceURL))

	instructions.WriteString("🔑 Enter this code when prompted:\n")
	instructions.WriteString(fmt.Sprintf("   %s\n\n", userCode))

	instructions.WriteString("⏳ Waiting for authentication...\n")
	instructions.WriteString("   (This will complete automatically once you authenticate)\n\n")

	instructions.WriteString("💡 Instructions:\n")
	instructions.WriteString("   1. Open the URL on your phone or scan the QR code\n")
	instructions.WriteString("   2. Sign in with your corporate credentials\n")
	instructions.WriteString("   3. Use your passkey (Face ID/Touch ID) if available\n")
	instructions.WriteString("   4. Grant permission for SSH access\n")
	instructions.WriteString("   5. Return to this terminal - access will be granted automatically\n\n")

	instructions.WriteString("═══════════════════════════════════════════════════════════════\n")

	return instructions.String()
}

// FormatConsoleInstructions formats instructions for console login
func FormatConsoleInstructions(deviceURL, userCode, qrCode string) string {
	var instructions strings.Builder

	instructions.WriteString("\n")
	instructions.WriteString("╔════════════════════════════════════════════════════════════════╗\n")
	instructions.WriteString("║                  🔐 OIDC Authentication Required               ║\n")
	instructions.WriteString("╚════════════════════════════════════════════════════════════════╝\n\n")

	if qrCode != "" {
		instructions.WriteString("📱 Scan QR code with your phone:\n")
		instructions.WriteString(qrCode)
		instructions.WriteString("\n")
	}

	instructions.WriteString("Or visit: ")
	instructions.WriteString(deviceURL)
	instructions.WriteString("\n")
	instructions.WriteString("Enter code: ")
	instructions.WriteString(userCode)
	instructions.WriteString("\n\n")

	instructions.WriteString("⏳ Waiting for authentication...")

	return instructions.String()
}

// FormatGUIInstructions formats instructions for GUI applications
func FormatGUIInstructions(deviceURL, userCode, qrCode string) string {
	var instructions strings.Builder

	instructions.WriteString("Authentication Required\n\n")
	instructions.WriteString("Please complete authentication on your mobile device:\n\n")

	if qrCode != "" {
		instructions.WriteString("1. Scan the QR code with your mobile device, or\n")
		instructions.WriteString("2. Visit: ")
		instructions.WriteString(deviceURL)
		instructions.WriteString("\n")
	} else {
		instructions.WriteString("1. Visit: ")
		instructions.WriteString(deviceURL)
		instructions.WriteString("\n")
	}

	instructions.WriteString("3. Enter code: ")
	instructions.WriteString(userCode)
	instructions.WriteString("\n")
	instructions.WriteString("4. Complete authentication with your corporate credentials\n")
	instructions.WriteString("5. Use your passkey (Face ID/Touch ID) if available\n\n")

	instructions.WriteString("This dialog will close automatically once authentication is complete.")

	return instructions.String()
}

// FormatProgressIndicator formats a progress indicator for authentication
func FormatProgressIndicator(step int, total int, message string) string {
	progress := strings.Repeat("█", step) + strings.Repeat("░", total-step)
	percentage := (step * 100) / total
	return fmt.Sprintf("[%s] %d%% %s", progress, percentage, message)
}

// FormatAuthenticationSuccess formats a success message
func FormatAuthenticationSuccess(userEmail, sessionDuration string) string {
	var success strings.Builder

	success.WriteString("✅ Authentication Successful!\n")
	success.WriteString("═══════════════════════════════════════════════════════════════\n")
	success.WriteString(fmt.Sprintf("👤 Authenticated as: %s\n", userEmail))
	success.WriteString(fmt.Sprintf("⏰ Session duration: %s\n", sessionDuration))
	success.WriteString("🔑 SSH key provisioned automatically\n")
	success.WriteString("🛡️  All access logged for security compliance\n\n")

	return success.String()
}

// FormatAuthenticationError formats an error message
func FormatAuthenticationError(errorMsg string) string {
	var errorStr strings.Builder

	errorStr.WriteString("❌ Authentication Failed\n")
	errorStr.WriteString("═══════════════════════════════════════════════════════════════\n")
	errorStr.WriteString(fmt.Sprintf("Error: %s\n\n", errorMsg))

	errorStr.WriteString("Please try again or contact your system administrator.\n")

	return errorStr.String()
}

// FormatSpinner returns a spinner character for the given step
func FormatSpinner(step int) string {
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	index := step % len(spinners)
	if index < 0 {
		index += len(spinners)
	}
	return spinners[index]
}