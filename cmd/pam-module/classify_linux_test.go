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
// Since version 1 of the wire contract (#146, #179) requires_device is not read at
// all: a grant is success=true *and* status "authorized" *and* a user_id equal to
// the account being logged into, and nothing else. TestClassifyResponseFollowsTheV1Rule
// holds that rule; the tables after it cover every field the decision still reads
// with a value of the wrong JSON type. The rule is the same for all of them — with
// `auth sufficient pam_oidc.so`, PAM_SUCCESS is a login, so a reply the module
// cannot interpret must never produce one.

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
			// The only shape that is a grant.
			name:  "authorized",
			reply: `{"protocol_version":1,"status":"authorized","success":true,"session_id":"s","user_id":"testuser"}`,
			want:  int(pam.PAMSuccess),
		},
		{
			// A broker that predates protocol_version speaks version 1 by definition.
			name:  "authorized, protocol_version absent",
			reply: `{"status":"authorized","success":true,"session_id":"s","user_id":"testuser"}`,
			want:  int(pam.PAMSuccess),
		},
		{
			// Neither a grant nor a denial: the user has not visited the device URL
			// yet, and identity binding and require_groups are still to come.
			name:  "device flow started",
			reply: `{"protocol_version":1,"status":"pending","success":false,"session_id":"s","requires_device":true}`,
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
		{"success absent", `{"status":"authorized","session_id":"s","user_id":"testuser"}`},
		{"empty object", `{}`},
		{"success spelled differently", `{"Success":true,"user_id":"testuser"}`},

		// pending and success=true at once is a reply that contradicts itself.
		{"pending with success true", `{"status":"pending","success":true,"session_id":"s"}`},

		// A version this module does not implement may parse fine with "authorized"
		// meaning something new, so its fields are not read at all.
		{"a later protocol version", `{"protocol_version":2,"status":"authorized","success":true,"user_id":"testuser"}`},
		{"a negative protocol version", `{"protocol_version":-1,"status":"authorized","success":true,"user_id":"testuser"}`},

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

		// requires_device is not read, so a refusal that also asks for a device step
		// is still a refusal — not a pending device flow to sit and poll until the
		// login grace time runs out.
		{"a refusal that also wants a device step", `{"success":false,"requires_device":true}`, pam.PAMAuthError},

		// status says which kind of refusal; the error_code still selects the PAM
		// result, and success=false wins over a status that claims otherwise.
		{"denied", `{"status":"denied","success":false,"error_code":"POLICY_DENIED"}`, pam.PAMPermDenied},
		{"expired", `{"status":"expired","success":false,"error_code":"SESSION_EXPIRED"}`, pam.PAMAuthError},
		{"authorized but success false", `{"status":"authorized","success":false,"user_id":"testuser"}`, pam.PAMAuthError},
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

// The client half of the contract's one rule (#146, #179): access only on
// success=true *and* status "authorized", and only for the account being logged
// into. Every case here has success=true, so each is a reply the module would have
// granted before version 1.
func TestClassifyResponseFollowsTheV1Rule(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		reply string
		user  string
		want  pam.PAMResultCode
	}{
		{"the pre-v1 grant has no status", `{"success":true,"user_id":"testuser","requires_device":false}`, "testuser", pam.PAMAuthError},
		{"the pre-v1 device-flow reply", `{"success":true,"session_id":"s","requires_device":true}`, "testuser", pam.PAMAuthError},
		{"an unknown status", `{"status":"approved","success":true,"user_id":"testuser"}`, "testuser", pam.PAMAuthError},
		{"a status of the wrong type", `{"status":true,"success":true,"user_id":"testuser"}`, "testuser", pam.PAMAuthError},
		{"status differs in case", `{"status":"Authorized","success":true,"user_id":"testuser"}`, "testuser", pam.PAMAuthError},

		// Conformance item 3: the broker binds the identity to the account too, and
		// that is the point — it is a different process, and may be older.
		{"authorized for another account", `{"status":"authorized","success":true,"user_id":"root"}`, "testuser", pam.PAMAuthError},
		{"authorized with no user_id", `{"status":"authorized","success":true}`, "testuser", pam.PAMAuthError},
		{"authorized with an empty user_id", `{"status":"authorized","success":true,"user_id":""}`, "testuser", pam.PAMAuthError},
		{"user_id of the wrong type", `{"status":"authorized","success":true,"user_id":0}`, "testuser", pam.PAMAuthError},
		{"user_id is a prefix of the login", `{"status":"authorized","success":true,"user_id":"test"}`, "testuser", pam.PAMAuthError},
		{"the matching account", `{"status":"authorized","success":true,"user_id":"alice"}`, "alice", pam.PAMSuccess},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := classifyBrokerResponseFor(tc.reply, tc.user); got != int(tc.want) {
				t.Fatalf("classify(%s) for %s = %d, want %d", tc.reply, tc.user, got, int(tc.want))
			}
		})
	}
}

// protocol_version on a reply, per the table in the wire contract: absent, null and
// 0 are 1; a string or a non-integral number is read as absent, so 1; anything else
// is a version this module does not implement and is refused before any other
// field is read.
func TestClassifyResponseReadsTheReplyProtocolVersion(t *testing.T) {
	t.Parallel()

	const rest = `"status":"authorized","success":true,"user_id":"testuser"}`
	cases := []struct {
		version string
		want    pam.PAMResultCode
	}{
		{`null`, pam.PAMSuccess},
		{`0`, pam.PAMSuccess},
		{`1`, pam.PAMSuccess},
		{`"2"`, pam.PAMSuccess},
		{`1.5`, pam.PAMSuccess},
		{`2`, pam.PAMAuthInfoUnavail},
		{`-1`, pam.PAMAuthInfoUnavail},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()

			reply := `{"protocol_version":` + tc.version + `,` + rest
			if got := classifyBrokerResponse(reply); got != int(tc.want) {
				t.Fatalf("classify(%s) = %d, want %d", reply, got, int(tc.want))
			}
		})
	}
}

// Both ends, the contract's test for an extension field: delete it and the
// decision must not change. requires_device and requires_approval are what the
// broker sent before status existed, and making the grant depend on one of them is
// what version 1 replaced.
func TestClassifyResponseIgnoresTheLegacyHints(t *testing.T) {
	t.Parallel()

	bases := []string{
		`"status":"authorized","success":true,"user_id":"testuser"`,
		`"status":"pending","success":false,"session_id":"s"`,
		`"status":"denied","success":false,"error_code":"POLICY_DENIED"`,
	}
	hints := []string{
		`"requires_device":true`, `"requires_device":false`, `"requires_device":null`,
		`"requires_device":"false"`, `"requires_approval":true`,
	}

	for _, base := range bases {
		want := classifyBrokerResponse(`{` + base + `}`)
		for _, hint := range hints {
			reply := `{` + base + `,` + hint + `}`
			if got := classifyBrokerResponse(reply); got != want {
				t.Errorf("classify(%s) = %d, but %d without %s: a legacy hint changed the decision",
					reply, got, want, hint)
			}
		}
	}
}
