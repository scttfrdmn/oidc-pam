package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/skip2/go-qrcode"
)

// MaxQRCodeURILen is the longest URL GenerateQRCode will draw, in bytes.
//
// The art grows superlinearly with the URL it encodes, and the URL is the
// provider's verification_uri, so its size is the provider's to choose. Version 1
// of the oauth2-pam wire protocol bounds it at 200 bytes and skips the code above
// that rather than failing the login (#179): the URL and user code in the
// instructions are what the user acts on, and the art is a convenience. Every real
// verification URI is far shorter.
const MaxQRCodeURILen = 200

// ErrQRCodeURITooLong is returned by GenerateQRCode for a URL over
// MaxQRCodeURILen bytes.
var ErrQRCodeURITooLong = errors.New("URL too long to draw as a QR code")

// GenerateQRCode generates a QR code for the given URL
func GenerateQRCode(url string) (string, error) {
	if len(url) > MaxQRCodeURILen {
		return "", fmt.Errorf("%w: %d bytes, limit %d", ErrQRCodeURITooLong, len(url), MaxQRCodeURILen)
	}

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

// The Format*Instructions functions render the text a user acts on to complete a
// device flow: the verification URL and the user code, laid out for one login
// type. None of them carries QR art. Version 1 of the oauth2-pam wire protocol
// sends the art once, in the reply's own qr_code field, and a client that can draw
// it renders that field (#179); embedding it here as well put the largest field of
// the largest reply on the wire twice. The art is optional — a reply may have none
// — so this text must be complete without it, and does not mention it.

// FormatDeviceInstructions formats instructions for device flow authentication
func FormatDeviceInstructions(deviceURL, userCode string) string {
	var instructions strings.Builder

	instructions.WriteString("🔐 OIDC Authentication Required\n")
	instructions.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	instructions.WriteString("📱 Visit the following URL on your mobile device:\n")
	fmt.Fprintf(&instructions, "🔗 %s\n\n", deviceURL)

	instructions.WriteString("🔑 Enter this code when prompted:\n")
	fmt.Fprintf(&instructions, "   %s\n\n", userCode)

	instructions.WriteString("⏳ Waiting for authentication...\n")
	instructions.WriteString("   (This will complete automatically once you authenticate)\n\n")

	instructions.WriteString("💡 Instructions:\n")
	instructions.WriteString("   1. Open the URL on your phone\n")
	instructions.WriteString("   2. Sign in with your corporate credentials\n")
	instructions.WriteString("   3. Use your passkey (Face ID/Touch ID) if available\n")
	instructions.WriteString("   4. Grant permission for SSH access\n")
	instructions.WriteString("   5. Return to this terminal - access will be granted automatically\n\n")

	instructions.WriteString("═══════════════════════════════════════════════════════════════\n")

	return instructions.String()
}

// FormatConsoleInstructions formats instructions for console login
func FormatConsoleInstructions(deviceURL, userCode string) string {
	var instructions strings.Builder

	instructions.WriteString("\n")
	instructions.WriteString("╔════════════════════════════════════════════════════════════════╗\n")
	instructions.WriteString("║                  🔐 OIDC Authentication Required               ║\n")
	instructions.WriteString("╚════════════════════════════════════════════════════════════════╝\n\n")

	instructions.WriteString("Visit: ")
	instructions.WriteString(deviceURL)
	instructions.WriteString("\n")
	instructions.WriteString("Enter code: ")
	instructions.WriteString(userCode)
	instructions.WriteString("\n\n")

	instructions.WriteString("⏳ Waiting for authentication...")

	return instructions.String()
}

// FormatGUIInstructions formats instructions for GUI applications
func FormatGUIInstructions(deviceURL, userCode string) string {
	var instructions strings.Builder

	instructions.WriteString("Authentication Required\n\n")
	instructions.WriteString("Please complete authentication on your mobile device:\n\n")

	instructions.WriteString("1. Visit: ")
	instructions.WriteString(deviceURL)
	instructions.WriteString("\n")
	instructions.WriteString("2. Enter code: ")
	instructions.WriteString(userCode)
	instructions.WriteString("\n")
	instructions.WriteString("3. Complete authentication with your corporate credentials\n")
	instructions.WriteString("4. Use your passkey (Face ID/Touch ID) if available\n\n")

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
	fmt.Fprintf(&success, "👤 Authenticated as: %s\n", userEmail)
	fmt.Fprintf(&success, "⏰ Session duration: %s\n", sessionDuration)
	success.WriteString("🔑 SSH key provisioned automatically\n")
	success.WriteString("🛡️  All access logged for security compliance\n\n")

	return success.String()
}

// FormatAuthenticationError formats an error message
func FormatAuthenticationError(errorMsg string) string {
	var errorStr strings.Builder

	errorStr.WriteString("❌ Authentication Failed\n")
	errorStr.WriteString("═══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(&errorStr, "Error: %s\n\n", errorMsg)

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
