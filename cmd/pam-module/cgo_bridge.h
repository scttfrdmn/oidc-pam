#ifndef CGO_BRIDGE_H
#define CGO_BRIDGE_H

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

// PAM module name and version
#define PAM_MODULE_NAME "pam_oidc"
#define PAM_MODULE_VERSION "0.1.0"

// Size of the buffer a broker response is read into, NUL included.
//
// 16 KiB is the bound the oauth2-pam wire protocol (version 1) sets on a response:
// that project owns the broker<->module contract and this one consumes it (#179),
// so the number is taken from there rather than chosen here.
//
// This is one half of a contract with the broker: maxResponseSize in
// internal/ipc/response.go is the other, and TestResponseSizeMatchesTheModulesBuffer
// reads this file to hold the two equal. The broker never sends more than fits
// here — it degrades the response, and reports an error rather than a prefix of one
// — because a response that did not fit used to arrive truncated, fail to parse,
// and refuse every login on the host with nothing in syslog but "Failed to parse
// broker response". That was #162, with the buffer at 8 KiB and the QR art
// serialized into the response twice.
//
// There used to be a second, unused MAX_BUFFER_SIZE macro with the same value.
// Two names for one size is how a size ends up changed in one place only.
#define MAX_RESPONSE_SIZE 16384

// receive_auth_response results. A response that does not fit MAX_RESPONSE_SIZE is
// distinguished from a transport failure so the caller can say so: the two mean
// very different things to whoever is reading the log.
#define RECV_OK 0
#define RECV_ERROR (-1)
#define RECV_RESPONSE_TOO_LARGE (-2)
// Longest usable Unix socket path, taken from the platform's sockaddr_un
// (108 bytes on Linux, 104 on Darwin/BSD) so it can never disagree with it.
#define MAX_SOCKET_PATH (sizeof(((struct sockaddr_un *)0)->sun_path))

// Longest session ID the module will accept from the broker, matching
// maxSessionIDLen in internal/ipc/validate.go (plus the NUL).
#define MAX_SESSION_ID_SIZE 129

// Bounds the wire protocol (version 1) sets on the two fields that say where a
// login came from and where it is going: 45 bytes is an IPv6 literal with a zone,
// 253 a DNS name. The broker refuses anything longer
// (maxSourceIPLen/maxTargetHostLen in internal/ipc/validate.go), so the module
// declines to send it rather than having the login refused as INVALID_REQUEST.
#define MAX_SOURCE_IP_LEN 45
#define MAX_TARGET_HOST_LEN 253

// Default socket path for the OIDC broker. Must match the default of
// server.socket_path in pkg/config/config.go; override per-service with the
// `socket=<path>` module argument in /etc/pam.d/<service>.
#define SOCKET_PATH "/var/run/oidc-auth/broker.sock"

// How long, in seconds, pam_sm_authenticate will wait for the user to complete
// the device authorization flow before failing closed. The default stays below
// sshd's default LoginGraceTime (120 s) so sshd does not tear the session down
// mid-prompt; raising `timeout=` past that needs a matching LoginGraceTime.
#define DEFAULT_AUTH_TIMEOUT 90
#define MIN_AUTH_TIMEOUT 10
#define MAX_AUTH_TIMEOUT 900

// Bounds on the poll interval the broker asks for via metadata.polling_interval.
// The broker already clamps what it sends to [5, 3600] (pkg/auth/device_flow.go),
// so these exist only to keep a missing or malformed value from turning the
// polling loop into a busy loop or an unbounded wait.
#define DEFAULT_POLL_INTERVAL 5
#define MIN_POLL_INTERVAL 1
#define MAX_POLL_INTERVAL 60

// Options parsed from the module arguments in /etc/pam.d/<service>.
//
// debug belongs here, per invocation, rather than only in the module's global:
// the flag used to be set once and never cleared, so one service's `debug` turned
// on debug logging for every later authentication in the same process (#168).
typedef struct {
    char socket_path[MAX_SOCKET_PATH];
    int timeout_s;
    int debug;
} pam_oidc_options;

// Function prototypes
void parse_arguments(int argc, const char **argv, pam_oidc_options *opts);
void log_pam_message(int priority, const char *format, ...);
int debug_logging_enabled(void);
int connect_to_broker(const char *socket_path);
int get_user_info(pam_handle_t *pamh, const char **username, const char **service, const char **rhost, const char **tty);
const char *classify_login_type(const char *service, const char *tty);
int acct_mgmt_verdict(void);
int send_auth_request(int sock, const char *username, const char *service, const char *rhost, const char *tty);
int send_check_session_request(int sock, const char *session_id, const char *username);
int receive_auth_response(int sock, char *response, size_t response_size);
int perform_authentication(pam_handle_t *pamh, const char *socket_path, const char *username,
                           const char *service, const char *rhost, const char *tty, int timeout_s);
int display_message(pam_handle_t *pamh, const char *message);

#endif // CGO_BRIDGE_H
