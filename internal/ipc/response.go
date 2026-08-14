package ipc

import (
	"encoding/json"
	"net"

	"github.com/rs/zerolog/log"
)

// maxResponseSize is the largest response the broker will send to the PAM module,
// counting the newline that terminates it.
//
// The number comes from the oauth2-pam wire protocol (version 1), which bounds a
// response at 16 KiB and permits a client to refuse a larger one. That project owns
// the broker<->module contract and this one consumes it (#179), so this is not ours
// to pick.
//
// The module reads a response into a buffer of exactly this size
// (MAX_RESPONSE_SIZE in cmd/pam-module/cgo_bridge.h, held equal to this constant by
// TestResponseSizeMatchesTheModulesBuffer). Nothing larger can reach it: what
// arrived was a truncated prefix, json_tokener_parse failed on it, and every login
// on the host was refused with nothing in syslog but "Failed to parse broker
// response". That was #162 — at 8 KiB, with the QR art serialized twice (once as
// qr_code and again inside instructions), an ordinary device-flow response came
// within ~20 bytes of the limit.
//
// So the broker owns the size of what it sends: it degrades the response while it
// still can, and reports a parseable error when it cannot. The module's buffer is
// not something a client can be trusted to have.
//
// Admin payloads are deliberately exempt. oidc-admin is a Go client decoding a
// stream, and `sessions_list` on a busy host is legitimately larger than the
// module's buffer.
const maxResponseSize = 16384

// setDeviceInstructions renders the device-flow instructions into response,
// dropping the QR art if the response would not otherwise fit the PAM module's
// buffer.
//
// The art is by far the largest thing in a device response — several kilobytes,
// growing with the length of the verification URI — and it is a convenience: the
// instructions carry the same URL and user code as text. So a response that does
// not fit loses the art, not the login (#162). What is left is a login the user
// completes by typing the URL, instead of one that fails to parse.
func (s *Server) setDeviceInstructions(response *Response, loginType, qrCode string) {
	response.Instructions = s.formatInstructions(loginType, response.DeviceURL, response.DeviceCode, qrCode)

	if qrCode == "" || fitsModuleBuffer(response) {
		return
	}

	log.Warn().
		Str("user_id", response.UserID).
		Int("device_url_len", len(response.DeviceURL)).
		Msg("Device instructions do not fit the PAM module's buffer with the QR code; sending them without it")

	response.Instructions = s.formatInstructions(loginType, response.DeviceURL, response.DeviceCode, "")
}

// fitsModuleBuffer reports whether response, once marshalled and newline
// terminated, is small enough for the PAM module to read.
func fitsModuleBuffer(response *Response) bool {
	payload, err := json.Marshal(response)
	if err != nil {
		// Unmarshallable is not "fits": the caller's fallback is smaller, and
		// writeResponse will report the encoding failure.
		return false
	}
	return len(payload)+1 <= maxResponseSize
}

// writeResponse writes one newline-delimited JSON response.
//
// Responses to the PAM module (*Response) are additionally bounded by
// maxResponseSize: rather than a truncated prefix the module cannot parse, an
// oversized response is replaced by a small RESPONSE_TOO_LARGE failure, which the
// module maps to a distinct PAM result and which says in the broker log how big
// the response was.
func (s *Server) writeResponse(conn net.Conn, response any) {
	payload, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encode IPC response")
		return
	}

	if _, forModule := response.(*Response); forModule && len(payload)+1 > maxResponseSize {
		log.Error().
			Int("response_size", len(payload)+1).
			Int("max_response_size", maxResponseSize).
			Msg("Response does not fit the PAM module's buffer; sending RESPONSE_TOO_LARGE instead of a truncated response")

		payload, err = json.Marshal(&Response{
			Success:      false,
			ErrorCode:    "RESPONSE_TOO_LARGE",
			ErrorMessage: clientErrorMessage("RESPONSE_TOO_LARGE"),
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to encode RESPONSE_TOO_LARGE response")
			return
		}
	}

	if _, err := conn.Write(append(payload, '\n')); err != nil {
		log.Error().Err(err).Msg("Failed to write IPC response")
	}
}
