#include "cgo_bridge.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <poll.h>
#include <json-c/json.h>

// Total time budget for reading a complete broker response, in milliseconds.
#define RESPONSE_READ_TIMEOUT_MS 30000

// Whether this invocation logs at LOG_DEBUG, taken from the module arguments by
// parse_arguments.
//
// It has to be a global because log_pam_message is one, but it must not carry
// state from one invocation to the next: pam_sm_authenticate runs inside sshd,
// which serves many logins from one process and may run more than one service's
// stack there. Setting the flag and never clearing it meant a single `debug` on
// any stack turned on debug logging for every later authentication in that
// process, including those of services that did not ask for it (#168).
// parse_arguments now assigns this on every entry into the module, so an
// invocation gets exactly what its own arguments asked for.
static int debug_enabled = 0;

// The compiled-in default must fit in pam_oidc_options.socket_path, which is
// itself sized to the platform's sockaddr_un.sun_path.
_Static_assert(sizeof(SOCKET_PATH) <= MAX_SOCKET_PATH,
               "default SOCKET_PATH does not fit in pam_oidc_options.socket_path");

// Helper function to log messages
void log_pam_message(int priority, const char *format, ...) {
    if (!debug_enabled && priority == LOG_DEBUG) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    
    openlog(PAM_MODULE_NAME, LOG_PID, LOG_AUTHPRIV);
    vsyslog(priority, format, args);
    closelog();
    
    va_end(args);
}

// Whether debug logging is in force right now. This is a separate function so a
// Go test can watch the flag across two invocations — the module writes to syslog,
// which a test cannot read. See TestDebugFlagDoesNotOutliveItsInvocation.
int debug_logging_enabled(void) {
    return debug_enabled;
}

// Connect to the OIDC authentication broker
int connect_to_broker(const char *socket_path) {
    int sock;
    struct sockaddr_un addr;
    size_t path_len;

    log_pam_message(LOG_DEBUG, "Connecting to broker at %s", socket_path);

    // Refuse rather than silently truncate: a truncated path would connect to
    // the wrong socket, or to none at all with a confusing error.
    path_len = strlen(socket_path);
    if (path_len == 0 || path_len >= sizeof(addr.sun_path)) {
        log_pam_message(LOG_ERR, "Invalid broker socket path length: %zu", path_len);
        return -1;
    }

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        log_pam_message(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path, path_len + 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_pam_message(LOG_ERR, "Failed to connect to broker: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    log_pam_message(LOG_DEBUG, "Successfully connected to broker");
    return sock;
}

// Get user information from PAM handle.
//
// An item the service never set comes back as PAM_SUCCESS with a NULL pointer, so
// every one of these needs the substitute applied on NULL as well as on failure.
// Testing only the return value left *rhost or *tty NULL, and the next thing that
// happens to them is json_object_new_string(), i.e. strlen(NULL) — a crash of the
// auth child, which under sshd is the login. PAM_RHOST is unset for every local
// service (su, sudo, login, cron), and PAM_TTY for anything that is not on a
// terminal (#168).
int get_user_info(pam_handle_t *pamh, const char **username, const char **service, const char **rhost, const char **tty) {
    int retval;

    // Get username
    retval = pam_get_user(pamh, username, NULL);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Failed to get username: %s", pam_strerror(pamh, retval));
        return retval;
    }
    if (*username == NULL) {
        log_pam_message(LOG_ERR, "PAM returned no username");
        return PAM_USER_UNKNOWN;
    }

    // Get service name
    retval = pam_get_item(pamh, PAM_SERVICE, (const void**)service);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_WARNING, "Failed to get service name: %s", pam_strerror(pamh, retval));
    }
    if (retval != PAM_SUCCESS || *service == NULL) {
        *service = "unknown";
    }

    // Get remote host
    retval = pam_get_item(pamh, PAM_RHOST, (const void**)rhost);
    if (retval != PAM_SUCCESS || *rhost == NULL) {
        *rhost = "localhost";
    }

    // Get TTY
    retval = pam_get_item(pamh, PAM_TTY, (const void**)tty);
    if (retval != PAM_SUCCESS || *tty == NULL) {
        *tty = "unknown";
    }

    log_pam_message(LOG_DEBUG, "User info - username: %s, service: %s, rhost: %s, tty: %s",
                    *username, *service, *rhost, *tty);
    
    return PAM_SUCCESS;
}

// Classify the login for the broker's per-login-type policies. This must agree
// with GetLoginType in cgo_wrapper.go: the C module and the Go client would
// otherwise select different policies for the same login. See
// TestLoginTypeClassificationMatchesGo.
const char *classify_login_type(const char *service, const char *tty) {
    if (service == NULL) {
        service = "";
    }
    if (tty == NULL) {
        tty = "";
    }

    if (strcmp(service, "sshd") == 0) {
        return "ssh";
    }
    if (strcmp(service, "gdm") == 0 || strcmp(service, "lightdm") == 0 ||
        strcmp(service, "sddm") == 0) {
        return "gui";
    }
    if (strncmp(tty, "tty", 3) == 0) {
        return "console";
    }
    return "unknown";
}

// Derive the request's source_ip from PAM_RHOST: where the login is coming from.
//
// (#169) Returns NULL unless rhost really is an address. source_ip carries an
// address or nothing, and sshd hands PAM a resolved hostname when UseDNS is on;
// passing that through would be worse than omitting it, because the broker's
// network policies and IP allowlists would then evaluate a string that is not a
// location and nothing downstream re-resolves it. The unabridged rhost still goes
// out in metadata.rhost, which is audit context and decides nothing.
static const char *source_ip_from_rhost(const char *rhost) {
    char addr[MAX_SOURCE_IP_LEN + 1];
    struct in_addr v4;
    struct in6_addr v6;
    char *zone;
    size_t len;

    if (rhost == NULL) {
        return NULL;
    }
    len = strlen(rhost);
    if (len == 0 || len > MAX_SOURCE_IP_LEN) {
        return NULL;
    }

    // A zone ("fe80::1%eth0") names an interface on the sending host, which
    // inet_pton will not parse, so it is validated without and sent with.
    memcpy(addr, rhost, len);
    addr[len] = '\0';
    zone = strchr(addr, '%');
    if (zone != NULL) {
        *zone = '\0';
    }

    if (inet_pton(AF_INET, addr, &v4) == 1 || inet_pton(AF_INET6, addr, &v6) == 1) {
        return rhost;
    }
    return NULL;
}

// The request's target_host: the host being logged *into*, which is this one.
//
// (#169) Returns NULL rather than a guess when the name cannot be had or does not
// fit, since a wrong target_host selects the wrong per-resource policy.
static const char *this_host(char *buf, size_t size) {
    if (gethostname(buf, size) != 0) {
        return NULL; // includes ENAMETOOLONG: a truncated hostname is a wrong one
    }
    buf[size - 1] = '\0'; // POSIX does not promise termination on truncation
    if (buf[0] == '\0') {
        return NULL;
    }
    return buf;
}

// Send authentication request to broker
int send_auth_request(int sock, const char *username, const char *service, const char *rhost, const char *tty) {
    json_object *request = json_object_new_object();
    json_object *type = json_object_new_string("authenticate");
    json_object *user_id = json_object_new_string(username);
    json_object *metadata = json_object_new_object();
    json_object *service_obj = json_object_new_string(service);
    json_object *tty_obj = json_object_new_string(tty);

    const char *login_type_str = classify_login_type(service, tty);
    const char *source_ip = source_ip_from_rhost(rhost);
    char host_buf[MAX_TARGET_HOST_LEN + 1];
    const char *target_host = this_host(host_buf, sizeof(host_buf));

    // Add metadata
    json_object_object_add(metadata, "service", service_obj);
    json_object_object_add(metadata, "tty", tty_obj);
    json_object_object_add(metadata, "pid", json_object_new_int(getpid()));
    if (rhost != NULL && rhost[0] != '\0') {
        json_object_object_add(metadata, "rhost", json_object_new_string(rhost));
    }

    // Build request. Each value is added exactly once and owned by the tree, so
    // a single json_object_put(request) frees everything (L-11: previously the
    // login_type object was allocated but never attached, leaking each call).
    json_object_object_add(request, "type", type);
    json_object_object_add(request, "user_id", user_id);
    json_object_object_add(request, "login_type", json_object_new_string(login_type_str));
    // (#169) Both fields are omitted rather than sent empty when unknown: absent
    // and empty mean the same thing to the broker, and an omitted field is the one
    // the wire protocol describes. This used to send rhost as target_host and no
    // source_ip at all, which inverted the two ends of the connection.
    if (source_ip != NULL) {
        json_object_object_add(request, "source_ip", json_object_new_string(source_ip));
    }
    if (target_host != NULL) {
        json_object_object_add(request, "target_host", json_object_new_string(target_host));
    }
    json_object_object_add(request, "metadata", metadata);

    // Convert to string
    const char *request_str = json_object_to_json_string(request);
    size_t request_len = strlen(request_str);
    
    log_pam_message(LOG_DEBUG, "Sending auth request: %s", request_str);
    
    // Send request — retry until all bytes are sent
    ssize_t total_sent = 0;
    while (total_sent < (ssize_t)request_len) {
        ssize_t sent = send(sock, request_str + total_sent, request_len - total_sent, 0);
        if (sent == -1) {
            log_pam_message(LOG_ERR, "Failed to send request: %s", strerror(errno));
            json_object_put(request);
            return -1;
        }
        total_sent += sent;
    }
    
    json_object_put(request);
    return 0;
}

// Send a session-status request to the broker.
//
// user_id is required as well as session_id: Broker.CheckSession rejects a
// session whose owner does not match the requesting user with FORBIDDEN, so
// omitting it would make every poll fail.
int send_check_session_request(int sock, const char *session_id, const char *username) {
    json_object *request = json_object_new_object();

    json_object_object_add(request, "type", json_object_new_string("check_session"));
    json_object_object_add(request, "session_id", json_object_new_string(session_id));
    json_object_object_add(request, "user_id", json_object_new_string(username));

    const char *request_str = json_object_to_json_string(request);
    size_t request_len = strlen(request_str);

    log_pam_message(LOG_DEBUG, "Sending session check request: %s", request_str);

    ssize_t total_sent = 0;
    while (total_sent < (ssize_t)request_len) {
        ssize_t sent = send(sock, request_str + total_sent, request_len - total_sent, 0);
        if (sent == -1) {
            log_pam_message(LOG_ERR, "Failed to send session check request: %s", strerror(errno));
            json_object_put(request);
            return -1;
        }
        total_sent += sent;
    }

    json_object_put(request);
    return 0;
}

// Receive authentication response from broker.
//
// The broker writes a single newline-delimited JSON object (json.Encoder.Encode
// appends '\n'). A single recv() can return only the first TCP segment, which
// truncates large responses and breaks JSON parsing. Loop on recv() until the
// newline delimiter is seen, the buffer is full, or the connection closes,
// bounded by a total read timeout so a stalled/hostile broker cannot hang the
// PAM stack.
int receive_auth_response(int sock, char *response, size_t response_size) {
    if (response_size == 0) {
        return RECV_ERROR;
    }

    size_t total = 0;
    const size_t cap = response_size - 1; // reserve space for NUL

    while (total < cap) {
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;

        int pr = poll(&pfd, 1, RESPONSE_READ_TIMEOUT_MS);
        if (pr == 0) {
            log_pam_message(LOG_ERR, "Timed out waiting for broker response");
            return RECV_ERROR;
        }
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_pam_message(LOG_ERR, "poll() failed waiting for response: %s", strerror(errno));
            return RECV_ERROR;
        }

        ssize_t received = recv(sock, response + total, cap - total, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_pam_message(LOG_ERR, "Failed to receive response: %s", strerror(errno));
            return RECV_ERROR;
        }
        if (received == 0) {
            // Connection closed by broker. Accept whatever we have if it forms a
            // complete line; otherwise treat as an error.
            break;
        }

        total += (size_t)received;
        response[total] = '\0';

        // Stop as soon as we have a complete newline-delimited message.
        if (memchr(response, '\n', total) != NULL) {
            break;
        }
    }

    if (total == 0) {
        log_pam_message(LOG_ERR, "Connection closed by broker before any response");
        return RECV_ERROR;
    }

    response[total] = '\0';

    // A full buffer with no end of message in it is the beginning of a response,
    // not a response. Returning success here is what made #162 silent: the caller
    // handed the truncated JSON to json_tokener_parse, which failed, and every
    // login on the host was refused with nothing to go on but "Failed to parse
    // broker response". The broker is responsible for not sending more than
    // MAX_RESPONSE_SIZE; this is what happens when it does anyway.
    if (total >= cap && memchr(response, '\n', total) == NULL) {
        log_pam_message(LOG_ERR,
                        "Broker response does not fit this module's %zu-byte buffer "
                        "(%zu bytes read with no end of message)",
                        response_size, total);
        return RECV_RESPONSE_TOO_LARGE;
    }

    // The size, never the body. A response carries the live device code, the
    // user's email and groups, and whatever else the broker<->module contract
    // grows next; this module cannot know what is in one. syslog is not the place
    // for it — LOG_AUTHPRIV is retained, shipped off the host and readable by
    // everyone who can read auth.log, and `debug` is turned on by an operator
    // debugging a login, not by the user whose response it is (#168).
    log_pam_message(LOG_DEBUG, "Received %zu-byte broker response", total);

    return RECV_OK;
}

// Display message to user
int display_message(pam_handle_t *pamh, const char *message) {
    struct pam_message msg;
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;
    struct pam_conv *conv;
    int retval;
    
    retval = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Failed to get conversation function: %s", pam_strerror(pamh, retval));
        return retval;
    }

    // PAM_SUCCESS does not promise a usable conversation. A service that set none,
    // or set one with a NULL function, hands back exactly this — and calling
    // through it killed the auth child mid-login, which under sshd is the login
    // itself (#168). Nothing can be shown to this user, which is not a reason to
    // crash: the caller carries on and the login can still be completed from the
    // device code the user already has, or it times out and is refused.
    if (conv == NULL || conv->conv == NULL) {
        log_pam_message(LOG_WARNING, "No PAM conversation function available; not showing message to user");
        return PAM_CONV_ERR;
    }

    msg.msg_style = PAM_TEXT_INFO;
    msg.msg = message;

    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Failed to display message: %s", pam_strerror(pamh, retval));
        return retval;
    }
    
    if (resp) {
        if (resp->resp) {
            free(resp->resp);
        }
        free(resp);
    }
    
    return PAM_SUCCESS;
}

// There was a prompt_user() here. It had no caller — this module never asks the
// user for input, since the device flow happens in the user's browser — and it
// copied a conversation reply into a buffer whose size only its caller knew
// (#168). Deleted rather than left for someone to wire up. The device flow needs
// display_message and nothing else.

// Parse module arguments
// Parse the module arguments from /etc/pam.d/<service> into opts, which is
// always fully initialized to the defaults first.
//
// These arguments come from a root-owned PAM configuration file and are
// therefore trusted, unlike oidc-pam-helper's argv, which may come from an
// unprivileged caller (see L-6). Recognized arguments:
//
//   debug             Log at LOG_DEBUG to syslog, for this invocation only.
//   socket=<path>     Absolute path to the broker's Unix socket. Defaults to
//                     SOCKET_PATH, which matches the broker's own default for
//                     server.socket_path.
//   timeout=<seconds> How long to wait for the user to complete the device
//                     authorization flow. Clamped to
//                     [MIN_AUTH_TIMEOUT, MAX_AUTH_TIMEOUT]; this is the only
//                     place that bound is applied, so perform_authentication
//                     can be driven with a short budget from tests.
//
// Anything else is ignored with a warning, so a typo or a stale argument shows
// up in the log instead of silently doing nothing.
void parse_arguments(int argc, const char **argv, pam_oidc_options *opts) {
    int i;

    // Defaults first, so a caller can rely on opts being complete even when
    // argc is 0 or an argument is rejected below.
    memset(opts, 0, sizeof(*opts));
    memcpy(opts->socket_path, SOCKET_PATH, sizeof(SOCKET_PATH));
    opts->timeout_s = DEFAULT_AUTH_TIMEOUT;

    // Debug is settled before anything else is parsed: this assignment is what
    // stops a previous invocation's `debug` from still being in force (#168), and
    // doing it in its own pass means the messages logged below obey this
    // invocation's arguments whatever order they arrive in.
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            opts->debug = 1;
        }
    }
    debug_enabled = opts->debug;
    if (opts->debug) {
        log_pam_message(LOG_DEBUG, "Debug mode enabled");
    }

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            continue; // handled above
        } else if (strncmp(argv[i], "socket=", 7) == 0) {
            const char *path = argv[i] + 7;
            size_t len = strlen(path);

            if (path[0] != '/') {
                log_pam_message(LOG_ERR, "Ignoring socket= argument: path must be absolute (got '%s'); using %s",
                                path, opts->socket_path);
            } else if (len >= sizeof(opts->socket_path)) {
                log_pam_message(LOG_ERR, "Ignoring socket= argument: path is %zu bytes, limit is %zu; using %s",
                                len, sizeof(opts->socket_path) - 1, opts->socket_path);
            } else {
                memcpy(opts->socket_path, path, len + 1);
                log_pam_message(LOG_DEBUG, "Using broker socket: %s", opts->socket_path);
            }
        } else if (strncmp(argv[i], "timeout=", 8) == 0) {
            const char *value = argv[i] + 8;
            char *end = NULL;
            long seconds;

            errno = 0;
            seconds = strtol(value, &end, 10);
            if (errno != 0 || end == value || *end != '\0') {
                log_pam_message(LOG_ERR, "Ignoring timeout= argument: '%s' is not a number; using %d",
                                value, opts->timeout_s);
            } else if (seconds < MIN_AUTH_TIMEOUT || seconds > MAX_AUTH_TIMEOUT) {
                log_pam_message(LOG_ERR, "Ignoring timeout=%ld: outside [%d, %d]; using %d",
                                seconds, MIN_AUTH_TIMEOUT, MAX_AUTH_TIMEOUT, opts->timeout_s);
            } else {
                opts->timeout_s = (int)seconds;
                log_pam_message(LOG_DEBUG, "Device authorization timeout: %d seconds", opts->timeout_s);
            }
        } else if (strncmp(argv[i], "config=", 7) == 0) {
            // Accepted for compatibility with configs shipped before v0.4.3.
            // This module reads no configuration file of its own; everything
            // comes from the broker over the socket.
            log_pam_message(LOG_WARNING, "Ignoring config=%s: pam_oidc reads no configuration file", argv[i] + 7);
        } else {
            log_pam_message(LOG_WARNING, "Ignoring unrecognized module argument: %s", argv[i]);
        }
    }
}

// Sentinel returned by classify_response for a device flow that has been started
// but not yet completed. Every PAM_* return code is non-negative, so a negative
// value cannot collide with one.
#define BROKER_PENDING (-1)

// Read a string field, or NULL if it is absent or JSON null. The result points
// into obj and is only valid while obj is alive.
static const char *json_get_string(json_object *obj, const char *key) {
    json_object *field = NULL;

    if (!json_object_object_get_ex(obj, key, &field) || field == NULL) {
        return NULL;
    }
    return json_object_get_string(field);
}

// Read a boolean field, or fallback if it is absent.
static int json_get_bool(json_object *obj, const char *key, int fallback) {
    json_object *field = NULL;

    if (!json_object_object_get_ex(obj, key, &field) || field == NULL) {
        return fallback;
    }
    return json_object_get_boolean(field);
}

// Read the poll interval the broker asked for, clamped into a sane range. An
// absent, non-numeric or out-of-range value falls back to DEFAULT_POLL_INTERVAL
// rather than being trusted.
static int response_poll_interval(json_object *obj) {
    json_object *metadata = NULL, *field = NULL;
    int interval;

    if (!json_object_object_get_ex(obj, "metadata", &metadata) || metadata == NULL) {
        return DEFAULT_POLL_INTERVAL;
    }
    if (!json_object_object_get_ex(metadata, "polling_interval", &field) || field == NULL) {
        return DEFAULT_POLL_INTERVAL;
    }

    interval = json_object_get_int(field);
    if (interval < MIN_POLL_INTERVAL) {
        return MIN_POLL_INTERVAL;
    }
    if (interval > MAX_POLL_INTERVAL) {
        return MAX_POLL_INTERVAL;
    }
    return interval;
}

// Map a broker error_code onto a PAM result. This mirrors errorCodeToPAMResult
// in pam.go; keep the two in step.
//
// SESSION_NOT_FOUND, SESSION_EXPIRED and FORBIDDEN are denials, not transient
// failures: the broker deletes the session when identity binding fails, when
// require_groups rejects the user, when device-flow polling fails, and when the
// session expires, so a poll that can no longer find its session means the
// authentication was refused.
static int map_error_code(const char *error_code) {
    if (error_code == NULL) {
        return PAM_AUTH_ERR;
    }
    if (strcmp(error_code, "RATE_LIMIT_EXCEEDED") == 0 ||
        strcmp(error_code, "RATE_LIMITED") == 0 ||
        strcmp(error_code, "TOO_MANY_CONCURRENT_AUTHS") == 0) {
        return PAM_MAXTRIES;
    }
    if (strcmp(error_code, "TOO_MANY_SESSIONS") == 0 ||
        strcmp(error_code, "POLICY_DENIED") == 0 ||
        strcmp(error_code, "NO_PROVIDER") == 0) {
        return PAM_PERM_DENIED;
    }
    return PAM_AUTH_ERR;
}

// Decide what a broker response means: a PAM result code, or BROKER_PENDING if
// the device flow is still in progress.
static int classify_response(json_object *obj) {
    json_object *success_obj = NULL;

    // A response we cannot interpret is not a grant.
    //
    // The type is checked, not just the presence: json_object_get_boolean answers
    // true for any non-empty JSON *string*, so `"success":"false"` used to be read
    // as a success (#168). The real broker emits a JSON bool, which is exactly why
    // nothing is given up by insisting on one here.
    if (!json_object_object_get_ex(obj, "success", &success_obj) ||
        !json_object_is_type(success_obj, json_type_boolean)) {
        log_pam_message(LOG_ERR, "Broker response has no boolean success field");
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (!json_object_get_boolean(success_obj)) {
        const char *code = json_get_string(obj, "error_code");
        const char *message = json_get_string(obj, "error_message");

        log_pam_message(LOG_INFO, "Broker refused authentication (error_code=%s): %s",
                        code != NULL ? code : "(none)",
                        message != NULL ? message : "(no message)");
        return map_error_code(code);
    }

    // success=true is not on its own a grant. The broker sets it *together with*
    // requires_device=true when it has merely started the device flow: the user
    // has not visited the device URL yet, and identity binding and
    // require_groups are still checked afterwards, in a background goroutine.
    // requires_device must therefore be tested before success is honored, or
    // `auth sufficient pam_oidc.so` short-circuits the auth stack and grants
    // login to anyone who can reach the broker.
    if (json_get_bool(obj, "requires_device", 0)) {
        return BROKER_PENDING;
    }

    return PAM_SUCCESS;
}

// Show a message to the user, tolerating a NULL handle so the authentication
// flow can be driven from tests without a PAM conversation.
static void show_message(pam_handle_t *pamh, const char *message) {
    if (pamh == NULL || message == NULL || message[0] == '\0') {
        return;
    }
    display_message(pamh, message);
}

// Seconds on a monotonic clock, so a wall-clock adjustment mid-login cannot
// extend or collapse the authentication budget.
static long monotonic_seconds(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        // Should not happen; degrade to the realtime clock rather than spinning.
        return (long)time(NULL);
    }
    return (long)ts.tv_sec;
}

static void sleep_seconds(long seconds) {
    struct timespec remaining;

    if (seconds <= 0) {
        return;
    }
    remaining.tv_sec = (time_t)seconds;
    remaining.tv_nsec = 0;

    while (nanosleep(&remaining, &remaining) == -1 && errno == EINTR) {
        // Interrupted by a signal; finish the remaining time.
    }
}

// The broker serves exactly one request per connection and then closes it, so
// every attempt — the initial authenticate and each poll — needs its own
// connection.
static int broker_recv_and_close(int sock, char *response, size_t response_size) {
    int rc = receive_auth_response(sock, response, response_size);
    close(sock);
    return rc;
}

// Map a failed read of a broker response onto a PAM result.
//
// PAM_AUTHINFO_UNAVAIL means "I could not reach an opinion": no broker, no reply,
// a reply that is not JSON. A response too large for this module's buffer is a
// different statement — the broker answered, and what is wrong is the contract
// between the two halves of this project, not the transport and not the user. It
// gets PAM_SERVICE_ERR ("error in service module") so that an operator reading
// auth.log can tell the two apart, and so the fix they look for is the response
// size rather than the broker's health. Both fail closed (#162).
static int recv_failure_result(int rc) {
    if (rc == RECV_RESPONSE_TOO_LARGE) {
        return PAM_SERVICE_ERR;
    }
    return PAM_AUTHINFO_UNAVAIL;
}

static int broker_authenticate_once(const char *socket_path, const char *username, const char *service,
                                    const char *rhost, const char *tty,
                                    char *response, size_t response_size) {
    int sock = connect_to_broker(socket_path);
    if (sock == -1) {
        log_pam_message(LOG_ERR, "Failed to connect to authentication broker");
        return RECV_ERROR;
    }
    if (send_auth_request(sock, username, service, rhost, tty) != 0) {
        close(sock);
        return RECV_ERROR;
    }
    return broker_recv_and_close(sock, response, response_size);
}

static int broker_check_session_once(const char *socket_path, const char *session_id, const char *username,
                                     char *response, size_t response_size) {
    int sock = connect_to_broker(socket_path);
    if (sock == -1) {
        log_pam_message(LOG_ERR, "Failed to reconnect to authentication broker while polling");
        return RECV_ERROR;
    }
    if (send_check_session_request(sock, session_id, username) != 0) {
        close(sock);
        return RECV_ERROR;
    }
    return broker_recv_and_close(sock, response, response_size);
}

// Run one full authentication against the broker and return a PAM result code.
//
// This is the whole of the auth phase, factored out of pam_sm_authenticate so it
// can be exercised against a fake broker from Go tests. pamh may be NULL, in
// which case no messages are shown to the user.
//
// timeout_s bounds the wait for the user to complete the device flow. It is
// clamped to [MIN_AUTH_TIMEOUT, MAX_AUTH_TIMEOUT] by parse_arguments, which is
// how pam_sm_authenticate always obtains it; a non-positive value here means
// "poll once, then give up".
//
// Only a transport or parse failure returns PAM_AUTHINFO_UNAVAIL ("I could not
// reach an opinion"), and only a response too large for this module's buffer
// returns PAM_SERVICE_ERR. Everything else — a refusal, a vanished session, an
// exhausted budget — is a denial, so the auth stack fails closed.
int perform_authentication(pam_handle_t *pamh, const char *socket_path, const char *username,
                           const char *service, const char *rhost, const char *tty, int timeout_s) {
    char response[MAX_RESPONSE_SIZE];
    char session_id[MAX_SESSION_ID_SIZE];
    json_object *response_obj;
    const char *session;
    int poll_interval;
    long deadline;
    int result;
    int rc;

    rc = broker_authenticate_once(socket_path, username, service, rhost, tty,
                                  response, sizeof(response));
    if (rc != RECV_OK) {
        return recv_failure_result(rc);
    }

    response_obj = json_tokener_parse(response);
    if (response_obj == NULL) {
        log_pam_message(LOG_ERR, "Failed to parse broker response");
        return PAM_AUTHINFO_UNAVAIL;
    }

    result = classify_response(response_obj);
    if (result != BROKER_PENDING) {
        if (result == PAM_SUCCESS) {
            log_pam_message(LOG_INFO, "Authentication successful for user: %s", username);
        }
        json_object_put(response_obj);
        return result;
    }

    // Device authorization started. Remember the session so we can poll it, then
    // tell the user where to go.
    session = json_get_string(response_obj, "session_id");
    if (session == NULL || session[0] == '\0') {
        log_pam_message(LOG_ERR, "Broker requires device authorization but returned no session_id");
        json_object_put(response_obj);
        return PAM_AUTHINFO_UNAVAIL;
    }
    if (strlen(session) >= sizeof(session_id)) {
        log_pam_message(LOG_ERR, "Broker returned an over-long session_id (%zu bytes)", strlen(session));
        json_object_put(response_obj);
        return PAM_AUTHINFO_UNAVAIL;
    }
    memcpy(session_id, session, strlen(session) + 1);

    poll_interval = response_poll_interval(response_obj);
    show_message(pamh, json_get_string(response_obj, "instructions"));
    json_object_put(response_obj);

    log_pam_message(LOG_INFO, "Waiting up to %ds for device authorization by user %s (session %s)",
                    timeout_s, username, session_id);

    deadline = monotonic_seconds() + (timeout_s > 0 ? timeout_s : 0);

    for (;;) {
        long now = monotonic_seconds();
        long remaining = deadline - now;

        // Wait before polling: the broker has only just handed out the device
        // code, so an immediate poll can only ever report "pending".
        sleep_seconds(remaining < poll_interval ? remaining : poll_interval);

        rc = broker_check_session_once(socket_path, session_id, username,
                                       response, sizeof(response));
        if (rc != RECV_OK) {
            return recv_failure_result(rc);
        }

        response_obj = json_tokener_parse(response);
        if (response_obj == NULL) {
            log_pam_message(LOG_ERR, "Failed to parse broker session-check response");
            return PAM_AUTHINFO_UNAVAIL;
        }

        result = classify_response(response_obj);
        json_object_put(response_obj);

        if (result != BROKER_PENDING) {
            if (result == PAM_SUCCESS) {
                log_pam_message(LOG_INFO, "Device authorization completed for user: %s", username);
            }
            return result;
        }

        if (monotonic_seconds() >= deadline) {
            log_pam_message(LOG_NOTICE, "Device authorization not completed within %ds for user %s; denying",
                            timeout_s, username);
            return PAM_AUTH_ERR;
        }
    }
}

// PAM authentication function
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username, *service, *rhost, *tty;
    pam_oidc_options opts;
    int retval;

    (void)flags; // PAM_SILENT / PAM_DISALLOW_NULL_AUTHTOK are not honored

    log_pam_message(LOG_INFO, "OIDC PAM authentication started (version %s)", PAM_MODULE_VERSION);

    parse_arguments(argc, argv, &opts);

    retval = get_user_info(pamh, &username, &service, &rhost, &tty);
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    log_pam_message(LOG_INFO, "Authenticating user: %s", username);

    retval = perform_authentication(pamh, opts.socket_path, username, service, rhost, tty, opts.timeout_s);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_INFO, "Authentication failed for user: %s (pam result %d)", username, retval);
    }
    return retval;
}

// PAM credential setting function
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; // no PAM items are read or set in this phase

    log_pam_message(LOG_DEBUG, "pam_sm_setcred called with flags: %d", flags);
    
    // Parse arguments
    pam_oidc_options opts;
    parse_arguments(argc, argv, &opts);
    
    // For OIDC authentication, we don't need to set traditional credentials
    // The broker handles token management
    return PAM_SUCCESS;
}

// The module's account-phase verdict, which is "no opinion".
//
// Authorization is enforced entirely in the auth phase (pam_sm_authenticate ->
// broker: identity binding, group membership, risk policy). This module has
// nothing to add in the account phase, so it returns PAM_IGNORE rather than
// PAM_SUCCESS.
//
// The distinction matters. PAM_SUCCESS from a module marked `sufficient`
// short-circuits the rest of the account stack, so `account sufficient
// pam_oidc.so` — which these example configs used to ship — silently disabled
// every account check after it: pam_time, pam_nologin, pam_access, account
// expiry, pam_unix's shadow checks. Answering a question it was never asked let
// pam_oidc rubber-stamp the account phase for every user.
//
// PAM_IGNORE is not counted toward the stack's result at all, so the modules
// after it decide. If pam_oidc is the *only* account module, an all-ignored
// stack yields PAM_PERM_DENIED: it fails closed rather than admitting everyone.
// The shipped configs use `account optional pam_oidc.so` alongside a real account
// module; see configs/pam/README.md.
//
// This is a separate function so a Go test can pin the value — see
// TestAcctMgmtHasNoOpinion.
int acct_mgmt_verdict(void) {
    return PAM_IGNORE;
}

// PAM account management function
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    int retval;
    
    log_pam_message(LOG_DEBUG, "pam_sm_acct_mgmt called with flags: %d", flags);
    
    // Parse arguments
    pam_oidc_options opts;
    parse_arguments(argc, argv, &opts);
    
    // Get username
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Failed to get username: %s", pam_strerror(pamh, retval));
        return retval;
    }
    
    log_pam_message(LOG_DEBUG, "Account management check for user: %s", username);

    return acct_mgmt_verdict();
}

// PAM session open function
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    int retval;
    
    log_pam_message(LOG_DEBUG, "pam_sm_open_session called with flags: %d", flags);
    
    // Parse arguments
    pam_oidc_options opts;
    parse_arguments(argc, argv, &opts);
    
    // Get username
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Failed to get username: %s", pam_strerror(pamh, retval));
        return retval;
    }
    
    log_pam_message(LOG_INFO, "Opening session for user: %s", username);
    
    // Here we could:
    // 1. Set up SSH keys for the user
    // 2. Configure environment variables
    // 3. Set up audit logging for the session
    
    return PAM_SUCCESS;
}

// PAM session close function
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    int retval;
    
    log_pam_message(LOG_DEBUG, "pam_sm_close_session called with flags: %d", flags);
    
    // Parse arguments
    pam_oidc_options opts;
    parse_arguments(argc, argv, &opts);
    
    // Get username
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Failed to get username: %s", pam_strerror(pamh, retval));
        return retval;
    }
    
    log_pam_message(LOG_INFO, "Closing session for user: %s", username);
    
    // Here we could:
    // 1. Clean up SSH keys
    // 2. Revoke tokens
    // 3. Log session closure
    
    return PAM_SUCCESS;
}

// PAM password change function
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; // password changes are not supported; nothing is read from PAM

    log_pam_message(LOG_DEBUG, "pam_sm_chauthtok called with flags: %d", flags);
    
    // Parse arguments
    pam_oidc_options opts;
    parse_arguments(argc, argv, &opts);
    
    // OIDC authentication doesn't support password changes through PAM
    // Password changes should be done through the identity provider
    return PAM_AUTHTOK_ERR;
}