//go:build linux

package main

import (
	"testing"

	"github.com/scttfrdmn/oidc-pam/pkg/pam"
)

// Tests for the two functions that turn a broker reply into a PAM result:
// classify_response (reached here through classify_response_text) and
// map_error_code. Between them they are the module's entire decision about whether
// a login is granted, refused, or still waiting on the device flow, and until now
// neither had a test of any kind — both are static, and the tests in this package
// drove them only through a fake broker whose replies resemble a real one's, while
// e2e drives an honest broker that cannot construct the replies these functions
// exist to reject. `classify_response` rewritten to `return PAM_SUCCESS`
// unconditionally was green in every suite in this repository (#197).
//
// Two grants had already gone in unnoticed exactly that way, which is the argument
// for testing the decision directly rather than only end to end:
//
//   - `"success":"false"` — a JSON string — read as a success by
//     json_object_get_boolean, which answers true for any non-empty string (#168).
//   - a non-boolean `requires_device` read as "no device authorization needed", so
//     success=true was honored on its own with no device flow, no identity binding
//     and no require_groups check (#201).
//
// Every field these two functions read is covered below with a value of the wrong
// JSON type: success, requires_device, error_code and error_message. The rule is
// the same for all of them — with `auth sufficient pam_oidc.so`, PAM_SUCCESS is a
// login, so a reply the module cannot interpret must never produce one.

// The replies the module is entitled to grant on, and the one it must hold on.
//
// A suite made only of denials would pass against a decision that denied
// everything, which would be a broken module (nobody could log in) with a green
// test run. These are what keep the tables below from being vacuous.
func TestClassifyResponseGrantsOnlyACompletedAuthentication(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		reply string
		want  int
	}{
		{
			// The only shape that is a grant: success=true and the broker has said,
			// with a real JSON false, that no device step is outstanding.
			name:  "success with requires_device false",
			reply: `{"success":true,"session_id":"s","user_id":"testuser","requires_device":false}`,
			want:  int(pam.PAMSuccess),
		},
		{
			// internal/ipc.Response declares requires_device with no omitempty, so
			// the real broker always sends it; absent can only come from a different
			// producer, and is read as "no device step".
			name:  "success with requires_device absent",
			reply: `{"success":true,"session_id":"s","user_id":"testuser"}`,
			want:  int(pam.PAMSuccess),
		},
		{
			// success=true *with* requires_device=true is the broker reporting that
			// it has only started the device flow. Neither a grant nor a denial: the
			// user has not visited the device URL yet, and identity binding and
			// require_groups are still to come.
			name:  "device flow started",
			reply: `{"success":true,"session_id":"s","requires_device":true}`,
			want:  brokerPending,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := classifyBrokerResponse(tc.reply); got != tc.want {
				t.Fatalf("classify(%s) = %d, want %d: the denial tables in this file prove "+
					"nothing unless the decision can still reach this answer",
					tc.reply, got, tc.want)
			}
		})
	}
}

// Anything the module cannot interpret is not a grant. PAM_AUTHINFO_UNAVAIL is the
// honest answer — "I could not reach an opinion" — and it fails the auth stack
// closed.
func TestClassifyResponseDeniesAnythingItCannotInterpret(t *testing.T) {
	t.Parallel()

	// Written as raw JSON text throughout: the JSON *type* of the value is the whole
	// point of each case, and a Go map could not express most of them.
	cases := []struct {
		name  string
		reply string
	}{
		// success of the wrong type. json_object_get_boolean answers true for any
		// non-empty JSON string and for a non-zero number, so each of these used to
		// be readable as a grant (#168).
		{"success is the string false", `{"success":"false","error_code":"AUTHENTICATION_FAILED"}`},
		{"success is the string true", `{"success":"true","user_id":"testuser"}`},
		{"success is the empty string", `{"success":"","user_id":"testuser"}`},
		{"success is the number 1", `{"success":1,"user_id":"testuser"}`},
		{"success is the number 0", `{"success":0}`},
		{"success is the float 1.0", `{"success":1.0,"user_id":"testuser"}`},
		{"success is null", `{"success":null,"session_id":"s"}`},
		{"success is an object", `{"success":{"ok":true},"user_id":"testuser"}`},
		{"success is an empty object", `{"success":{}}`},
		{"success is an array", `{"success":[true],"user_id":"testuser"}`},
		{"success is an empty array", `{"success":[]}`},

		// success absent entirely. A reply with no verdict in it is not a verdict.
		{"success absent", `{"session_id":"s","user_id":"testuser","requires_device":false}`},
		{"empty object", `{}`},
		{"success spelled differently", `{"Success":true,"user_id":"testuser"}`},

		// requires_device of the wrong type, with a real boolean success=true. This
		// is the dangerous half: anything not a JSON boolean was silently read as
		// false — "no device authorization needed" — and success=true was then
		// honored on its own (#201). JSON null is the worst of them, because
		// json_object_object_get_ex answers TRUE with a NULL object for it, so it
		// took the "absent" path rather than looking like a value at all.
		{"requires_device is null", `{"success":true,"session_id":"s","requires_device":null}`},
		{"requires_device is the string false", `{"success":true,"session_id":"s","requires_device":"false"}`},
		{"requires_device is the string true", `{"success":true,"session_id":"s","requires_device":"true"}`},
		{"requires_device is the empty string", `{"success":true,"session_id":"s","requires_device":""}`},
		{"requires_device is the number 0", `{"success":true,"session_id":"s","requires_device":0}`},
		{"requires_device is the number 1", `{"success":true,"session_id":"s","requires_device":1}`},
		{"requires_device is the float 0.0", `{"success":true,"session_id":"s","requires_device":0.0}`},
		{"requires_device is an empty object", `{"success":true,"session_id":"s","requires_device":{}}`},
		{"requires_device is an empty array", `{"success":true,"session_id":"s","requires_device":[]}`},

		// Not a JSON object at all. json_object_object_get_ex answers FALSE for
		// these, which is the "no success field" path — but only because it is
		// asked; a reply is not obliged to be the shape the module expects.
		{"top level is an array", `[]`},
		{"top level is an array of replies", `[{"success":true,"user_id":"testuser"}]`},
		{"top level is a string", `"success"`},
		{"top level is the string true", `"true"`},
		{"top level is a number", `1`},
		{"top level is a bare true", `true`},
		{"top level is null", `null`},

		// Not JSON. json_tokener_parse answers NULL, which is where the module's
		// "Failed to parse broker response" comes from.
		{"empty text", ``},
		{"not JSON", `not json at all`},
		{"truncated object", `{"success":true,"session_id":"s"`},
		{"only whitespace", `   `},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := classifyBrokerResponse(tc.reply)

			if got == int(pam.PAMSuccess) {
				t.Fatalf("classify(%s) = PAM_SUCCESS: a reply the module cannot interpret was "+
					"read as a grant, and with the shipped `auth sufficient pam_oidc.so` a "+
					"grant is a login", tc.reply)
			}
			if got == brokerPending {
				t.Fatalf("classify(%s) = BROKER_PENDING: an uninterpretable reply is not "+
					"something to keep polling on", tc.reply)
			}
			if got != int(pam.PAMAuthInfoUnavail) {
				t.Fatalf("classify(%s) = %d, want pam.PAMAuthInfoUnavail (%d)",
					tc.reply, got, int(pam.PAMAuthInfoUnavail))
			}
		})
	}
}

// A refusal stays a refusal whatever its error_code looks like. The code only
// selects which kind of denial it is; it can never turn one into a grant, and it
// must never turn one into "I could not reach an opinion" either, because that is
// the answer that tells an operator the broker is down when in fact it answered.
func TestClassifyResponseDeniesARefusal(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		reply string
		want  pam.PAMResultCode
	}{
		{"a recognized rate limit", `{"success":false,"error_code":"RATE_LIMIT_EXCEEDED"}`, pam.PAMMaxTries},
		{"a policy denial", `{"success":false,"error_code":"POLICY_DENIED"}`, pam.PAMPermDenied},
		{"an unknown code", `{"success":false,"error_code":"WHO_KNOWS"}`, pam.PAMAuthError},
		{"no code at all", `{"success":false}`, pam.PAMAuthError},

		// json_object_get_string does not read a string, it renders whatever it is
		// given: an error_code of 404 came back as the text "404" (#201). A value of
		// the wrong type is not a code the broker's contract can express, so it maps
		// as an unrecognized one rather than as text map_error_code might match.
		{"the code is a number", `{"success":false,"error_code":404}`, pam.PAMAuthError},
		{"the code is null", `{"success":false,"error_code":null}`, pam.PAMAuthError},
		{"the code is a bool", `{"success":false,"error_code":true}`, pam.PAMAuthError},
		{"the code is an object", `{"success":false,"error_code":{"code":"POLICY_DENIED"}}`, pam.PAMAuthError},
		{"the code is an array", `{"success":false,"error_code":["POLICY_DENIED"]}`, pam.PAMAuthError},

		// error_message is only logged, so the point of these is that reading it
		// cannot change the verdict or crash on the way to it.
		{
			"the message is an object",
			`{"success":false,"error_code":"POLICY_DENIED","error_message":{"m":1}}`,
			pam.PAMPermDenied,
		},
		{
			"the message is a number",
			`{"success":false,"error_code":"POLICY_DENIED","error_message":42}`,
			pam.PAMPermDenied,
		},
		{
			"the message is null",
			`{"success":false,"error_code":"POLICY_DENIED","error_message":null}`,
			pam.PAMPermDenied,
		},
		{
			"the message is an array",
			`{"success":false,"error_message":["nope"]}`,
			pam.PAMAuthError,
		},

		// success is read before requires_device, so a refusal that also asks for a
		// device step is still a refusal — not a pending device flow to sit and poll
		// until the login grace time runs out.
		{"a refusal that also wants a device step", `{"success":false,"requires_device":true}`, pam.PAMAuthError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := classifyBrokerResponse(tc.reply)

			if got == int(pam.PAMSuccess) {
				t.Fatalf("classify(%s) = PAM_SUCCESS: the broker refused this authentication",
					tc.reply)
			}
			if got == brokerPending {
				t.Fatalf("classify(%s) = BROKER_PENDING: a refusal is terminal, not something "+
					"to keep polling on", tc.reply)
			}
			if got != int(tc.want) {
				t.Fatalf("classify(%s) = %d, want %d", tc.reply, got, int(tc.want))
			}
		})
	}
}

// map_error_code on its own: which denial each broker error code becomes.
//
// Every answer here is a denial. The mapping exists so an operator reading auth.log
// can tell a rate limit from a policy refusal, not to decide whether to let anyone
// in, and nothing it is given — including NULL — may return PAM_SUCCESS.
func TestMapErrorCodeAlwaysDenies(t *testing.T) {
	t.Parallel()

	code := func(s string) *string { return &s }

	cases := []struct {
		name string
		code *string
		want pam.PAMResultCode
	}{
		// NULL: what the module has whenever error_code is absent or is not a JSON
		// string. Reached from classify_response on every malformed refusal.
		{"NULL", nil, pam.PAMAuthError},
		{"empty", code(""), pam.PAMAuthError},

		{"RATE_LIMIT_EXCEEDED", code("RATE_LIMIT_EXCEEDED"), pam.PAMMaxTries},
		// RATE_LIMITED is the code pkg/auth actually emits, and the C side maps it
		// where the comment above map_error_code says it mirrors
		// errorCodeToPAMResult in pkg/pam/pam.go — which does not list it, and so
		// answers PAM_AUTH_ERR for the same reply. Both are denials, so nothing is
		// unsafe here; the two are simply not in step, and this line pins the C
		// side's answer rather than papering over the difference.
		{"RATE_LIMITED", code("RATE_LIMITED"), pam.PAMMaxTries},
		{"TOO_MANY_CONCURRENT_AUTHS", code("TOO_MANY_CONCURRENT_AUTHS"), pam.PAMMaxTries},

		{"TOO_MANY_SESSIONS", code("TOO_MANY_SESSIONS"), pam.PAMPermDenied},
		{"POLICY_DENIED", code("POLICY_DENIED"), pam.PAMPermDenied},
		{"NO_PROVIDER", code("NO_PROVIDER"), pam.PAMPermDenied},

		// The denials the module reaches by way of a vanished session: the broker
		// deletes the session when identity binding fails, when require_groups
		// rejects the user, when device-flow polling fails, and when it expires, so
		// a poll that can no longer find its session was refused.
		{"SESSION_NOT_FOUND", code("SESSION_NOT_FOUND"), pam.PAMAuthError},
		{"SESSION_EXPIRED", code("SESSION_EXPIRED"), pam.PAMAuthError},
		{"FORBIDDEN", code("FORBIDDEN"), pam.PAMAuthError},
		{"AUTHENTICATION_FAILED", code("AUTHENTICATION_FAILED"), pam.PAMAuthError},
		{"INVALID_REQUEST", code("INVALID_REQUEST"), pam.PAMAuthError},

		// The comparison is exact, and an unrecognized code is a denial rather than
		// anything softer, so near-misses need no special handling to be safe.
		{"unknown", code("SOMETHING_NEW"), pam.PAMAuthError},
		{"wrong case", code("policy_denied"), pam.PAMAuthError},
		{"trailing space", code("POLICY_DENIED "), pam.PAMAuthError},
		{"prefix only", code("POLICY_"), pam.PAMAuthError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := mapBrokerErrorCode(tc.code)

			if got == pam.PAMSuccess {
				t.Fatalf("map_error_code(%s) = PAM_SUCCESS: this function is only ever reached "+
					"because the broker refused the authentication", tc.name)
			}
			if got != tc.want {
				t.Fatalf("map_error_code(%s) = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}
