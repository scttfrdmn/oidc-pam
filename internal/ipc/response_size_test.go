package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/auth"
)

// The two constants that must not drift: the broker's own cap and the buffer the
// PAM module reads a response into. If the module's buffer were the smaller of the
// two, the broker would happily send responses that arrive truncated — which is
// exactly #162, and it produced nothing in syslog but "Failed to parse broker
// response" on every login.
// moduleBufferSize reads MAX_RESPONSE_SIZE out of the module's header.
//
// Deliberately not cgo: this has to run on a developer's Mac, where the module
// itself cannot be compiled (#141). Reading the header is also the point — a test
// that used the Go constant for both sides would agree with itself no matter what
// either value was.
func moduleBufferSize(t *testing.T) int {
	t.Helper()

	const header = "../../cmd/pam-module/cgo_bridge.h"

	data, err := os.ReadFile(header)
	if err != nil {
		t.Fatalf("read %s: %v", header, err)
	}

	match := regexp.MustCompile(`(?m)^#define\s+MAX_RESPONSE_SIZE\s+(\d+)`).FindSubmatch(data)
	if match == nil {
		t.Fatalf("no MAX_RESPONSE_SIZE definition in %s; if it was renamed, update this test — "+
			"the two sizes must stay equal", header)
	}

	size, err := strconv.Atoi(string(match[1]))
	if err != nil {
		t.Fatalf("MAX_RESPONSE_SIZE is not a number: %v", err)
	}
	return size
}

func TestResponseSizeMatchesTheModulesBuffer(t *testing.T) {
	const header = "../../cmd/pam-module/cgo_bridge.h"

	if moduleBuffer := moduleBufferSize(t); moduleBuffer != maxResponseSize {
		t.Errorf("MAX_RESPONSE_SIZE in %s is %d but maxResponseSize is %d; the broker must not send "+
			"more than the module can read", header, moduleBuffer, maxResponseSize)
	}
}

// worstCaseDeviceResponse is the largest device-flow response the broker's own
// input validation permits: a verification URI at maxVerificationURILen, a user
// code at maxUserCodeLen, and every other field filled to its limit.
func worstCaseDeviceResponse(t *testing.T, withQR bool) *Response {
	t.Helper()

	// 512 and 64 are the caps validateDeviceAuthLengths enforces in
	// pkg/auth/device_flow.go. They are not exported; a change there that this does
	// not follow shows up as a failure here, which is the intent.
	deviceURL := "https://idp.example.com/device?user_code=" +
		strings.Repeat("u", 512-len("https://idp.example.com/device?user_code="))
	deviceCode := strings.Repeat("C", 64)

	qrCode := ""
	if withQR {
		var err error
		qrCode, err = auth.GenerateQRCode(deviceURL)
		if err != nil {
			t.Fatalf("GenerateQRCode: %v", err)
		}
	}

	return &Response{
		Success:        true,
		UserID:         strings.Repeat("u", maxUserIDLen),
		Email:          strings.Repeat("e", 200) + "@example.com",
		Groups:         []string{"platform-engineering", "hpc-users", "cluster-admins"},
		SessionID:      strings.Repeat("s", maxSessionIDLen),
		DeviceCode:     deviceCode,
		DeviceURL:      deviceURL,
		ExpiresAt:      time.Now().Add(15 * time.Minute),
		SSHPublicKey:   "ssh-rsa " + strings.Repeat("A", 716) + " user@oidc-pam-1755000000",
		RequiresDevice: true,
		Instructions:   auth.FormatDeviceInstructions(deviceURL, deviceCode, qrCode),
		RiskScore:      42,
		Metadata: map[string]interface{}{
			"provider":         "keycloak",
			"polling_interval": 5,
		},
	}
}

// The acceptance test for #162: the response the module actually has to parse has
// to fit in its buffer.
//
// Both rungs are asserted here. Without the art there must be room to spare, or
// there is no degradation left and every such login fails; with the art it should
// fit too, so that the ladder is a bound on the pathological case rather than
// something an ordinary long-URI login trips.
func TestWorstCaseDeviceResponseFits(t *testing.T) {
	withoutQR := worstCaseDeviceResponse(t, false)
	if !fitsModuleBuffer(withoutQR) {
		payload, err := json.Marshal(withoutQR)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		t.Fatalf("the worst-case device response without the QR art is %d bytes, over the module's %d-byte "+
			"buffer: there is no degradation left and every such login fails to parse",
			len(payload)+1, maxResponseSize)
	}

	withQR := worstCaseDeviceResponse(t, true)
	payload, err := json.Marshal(withQR)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	t.Logf("worst case with QR art: %d bytes (module buffer %d)", len(payload)+1, maxResponseSize)
	if !fitsModuleBuffer(withQR) {
		t.Errorf("the worst-case device response with the QR art is %d bytes, over the module's %d-byte "+
			"buffer: the longest verification URI the broker accepts would lose its QR code",
			len(payload)+1, maxResponseSize)
	}
}

// The first rung of the ladder: a device response that does not fit with the QR
// art keeps the URL and the code and loses the art, so the user can still finish
// the login.
func TestDeviceInstructionsDropTheQRArtWhenTheResponseWouldNotFit(t *testing.T) {
	response := worstCaseDeviceResponse(t, false)
	qrCode, err := auth.GenerateQRCode(response.DeviceURL)
	if err != nil {
		t.Fatalf("GenerateQRCode: %v", err)
	}

	// The worst case the broker's own validation permits fits with the art, so
	// something else has to push this response over: group membership, which is the
	// one field in a response nothing bounds — it is whatever the IdP put in the
	// token. (A response that overflows even without the art is writeResponse's
	// problem, and it sends a parseable RESPONSE_TOO_LARGE rather than a prefix.)
	for {
		probe := *response
		probe.Instructions = auth.FormatDeviceInstructions(response.DeviceURL, response.DeviceCode, qrCode)
		if !fitsModuleBuffer(&probe) {
			break
		}
		response.Groups = append(response.Groups, fmt.Sprintf("research-computing-group-%03d", len(response.Groups)))
	}
	t.Logf("overflowed the module's %d-byte buffer at %d group memberships", maxResponseSize, len(response.Groups))

	(&Server{}).setDeviceInstructions(response, "ssh", qrCode)

	if !fitsModuleBuffer(response) {
		payload, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			t.Fatalf("Marshal: %v", marshalErr)
		}
		t.Fatalf("device response is %d bytes, over the module's %d-byte buffer", len(payload)+1, maxResponseSize)
	}
	if strings.Contains(response.Instructions, qrCode) {
		t.Error("the QR art was kept in a response that does not fit the module's buffer")
	}
	// Dropping the art must not drop what the user needs to act on.
	if !strings.Contains(response.Instructions, response.DeviceURL) {
		t.Error("instructions no longer contain the verification URL")
	}
	if !strings.Contains(response.Instructions, response.DeviceCode) {
		t.Error("instructions no longer contain the user code")
	}
}

// A QR code that does fit is kept: the degradation is a response to size, not a
// removal of the feature.
func TestDeviceInstructionsKeepAQRCodeThatFits(t *testing.T) {
	response := &Response{
		Success:        true,
		SessionID:      "sess-1",
		DeviceCode:     "WDJB-MJHT",
		DeviceURL:      "https://idp.example.com/device",
		RequiresDevice: true,
	}
	qrCode, err := auth.GenerateQRCode(response.DeviceURL)
	if err != nil {
		t.Fatalf("GenerateQRCode: %v", err)
	}

	(&Server{}).setDeviceInstructions(response, "ssh", qrCode)

	if !strings.Contains(response.Instructions, qrCode) {
		t.Error("a QR code that fits the module's buffer was dropped")
	}
	if !fitsModuleBuffer(response) {
		t.Error("an ordinary device response does not fit the module's buffer")
	}
}

// A response too large for the module must arrive as a response, not as a
// truncated prefix of one: the module can report a distinct failure for the first
// and can only fail to parse the second.
func TestWriteResponseReplacesAnOversizedResponse(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	oversized := &Response{
		Success:      true,
		SessionID:    "sess-1",
		Instructions: strings.Repeat("Q", maxResponseSize*2),
	}

	go func() {
		defer func() { _ = server.Close() }()
		(&Server{}).writeResponse(server, oversized)
	}()

	payload, err := readOneResponse(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(payload) > maxResponseSize {
		t.Fatalf("wrote %d bytes, over the module's %d-byte buffer", len(payload), maxResponseSize)
	}

	var got Response
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("the module would fail to parse what was sent: %v", err)
	}
	if got.Success {
		t.Error("an oversized response was replaced by a success")
	}
	if got.ErrorCode != "RESPONSE_TOO_LARGE" {
		t.Errorf("error_code = %q, want RESPONSE_TOO_LARGE", got.ErrorCode)
	}
}

// responseOfExactWireSize returns a response whose marshalled form plus its
// terminating newline is exactly want bytes, padding Instructions to get there.
func responseOfExactWireSize(t *testing.T, want int) *Response {
	t.Helper()

	response := &Response{Success: true, SessionID: "sess-1"}
	payload, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// One ASCII byte of Instructions costs one byte of JSON; the field itself costs
	// the key, the quotes and the comma, which is why the padding is measured rather
	// than computed.
	response.Instructions = ""
	for pad := want - (len(payload) + 1); pad > 0; pad-- {
		response.Instructions = strings.Repeat("Q", pad)
		payload, err = json.Marshal(response)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if len(payload)+1 == want {
			return response
		}
	}
	t.Fatalf("could not build a response of exactly %d wire bytes", want)
	return nil
}

// The boundary itself, in both directions (#223).
//
// The module reserves the last byte of its buffer for the NUL it writes, so it reads
// at most MAX_RESPONSE_SIZE-1 bytes and needs the newline inside them. A response of
// exactly MAX_RESPONSE_SIZE bytes therefore arrives as a full buffer with no end of
// message in it, which the module refuses — the #162 failure, at the one size the cap
// was meant to make safe. The broker used to send it: this pins the last size it may.
func TestTheLargestResponseTheBrokerSendsIsOneTheModuleCanRead(t *testing.T) {
	// Derived from the header, not from maxResponseWire: the whole bug was the Go
	// side's idea of the limit disagreeing with what the C side can read, and a test
	// that asked the Go constant about itself would have passed either way.
	readable := moduleBufferSize(t) - 1 // the module reserves the last byte for its NUL

	atLimit := responseOfExactWireSize(t, readable)
	if !fitsModuleBuffer(atLimit) {
		t.Errorf("a %d-byte response is rejected, but that is exactly what the module can read: "+
			"the broker is degrading responses it did not need to", readable)
	}

	// One byte more is the first size the module cannot read out of its buffer, and
	// is also the size the broker sent before #223.
	overLimit := responseOfExactWireSize(t, readable+1)
	if fitsModuleBuffer(overLimit) {
		t.Errorf("a %d-byte response is treated as fitting, but the module reads at most %d bytes "+
			"of its %d-byte buffer and would find no newline in them",
			readable+1, readable, moduleBufferSize(t))
	}

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() {
		defer func() { _ = server.Close() }()
		(&Server{}).writeResponse(server, overLimit)
	}()

	payload, err := readOneResponse(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	// +1 for the newline readOneResponse stripped: what went on the wire.
	if len(payload)+1 > readable {
		t.Fatalf("writeResponse put %d bytes on the wire, over the %d the module can read",
			len(payload)+1, readable)
	}
	var got Response
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("the module would fail to parse what was sent: %v", err)
	}
	if got.ErrorCode != "RESPONSE_TOO_LARGE" {
		t.Errorf("error_code = %q, want RESPONSE_TOO_LARGE", got.ErrorCode)
	}
}

// Admin payloads are exempt: oidc-admin decodes a stream, and sessions_list on a
// busy host is legitimately bigger than the PAM module's buffer. Capping them
// would break the tool that operators use to see the sessions.
func TestWriteResponseDoesNotCapAdminPayloads(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	big := map[string]string{"sessions": strings.Repeat("s", maxResponseSize*2)}

	go func() {
		defer func() { _ = server.Close() }()
		(&Server{}).writeResponse(server, big)
	}()

	payload, err := readOneResponse(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(payload) < maxResponseSize {
		t.Fatalf("an admin payload of %d bytes was truncated to %d", maxResponseSize*2, len(payload))
	}
	var got map[string]string
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("admin payload did not survive the round trip: %v", err)
	}
}

// readOneResponse reads the newline-delimited response writeResponse sends,
// without the newline.
func readOneResponse(conn net.Conn) ([]byte, error) {
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return line, err
	}
	return line[:len(line)-1], nil
}
