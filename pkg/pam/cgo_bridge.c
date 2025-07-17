#include "cgo_bridge.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <json-c/json.h>

// Global variables
static int debug_enabled = 0;
static char config_path[256] = "/etc/oidc-auth/pam.conf";

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

// CGO-compatible logging function (no variadic arguments)
void log_pam_message_string(int priority, const char *message) {
    if (!debug_enabled && priority == LOG_DEBUG) {
        return;
    }
    
    openlog(PAM_MODULE_NAME, LOG_PID, LOG_AUTHPRIV);
    syslog(priority, "%s", message);
    closelog();
}

// Connect to the OIDC authentication broker
int connect_to_broker(const char *socket_path) {
    int sock;
    struct sockaddr_un addr;
    
    log_pam_message(LOG_DEBUG, "Connecting to broker at %s", socket_path);
    
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        log_pam_message(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_pam_message(LOG_ERR, "Failed to connect to broker: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    log_pam_message(LOG_DEBUG, "Successfully connected to broker");
    return sock;
}

// Get user information from PAM handle
int get_user_info(pam_handle_t *pamh, const char **username, const char **service, const char **rhost, const char **tty) {
    int retval;
    
    // Get username
    retval = pam_get_user(pamh, username, NULL);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Failed to get username: %s", pam_strerror(pamh, retval));
        return retval;
    }
    
    // Get service name
    retval = pam_get_item(pamh, PAM_SERVICE, (const void**)service);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_WARNING, "Failed to get service name: %s", pam_strerror(pamh, retval));
        *service = "unknown";
    }
    
    // Get remote host
    retval = pam_get_item(pamh, PAM_RHOST, (const void**)rhost);
    if (retval != PAM_SUCCESS) {
        *rhost = "localhost";
    }
    
    // Get TTY
    retval = pam_get_item(pamh, PAM_TTY, (const void**)tty);
    if (retval != PAM_SUCCESS) {
        *tty = "unknown";
    }
    
    log_pam_message(LOG_DEBUG, "User info - username: %s, service: %s, rhost: %s, tty: %s",
                    *username, *service, *rhost, *tty);
    
    return PAM_SUCCESS;
}

// Send authentication request to broker
int send_auth_request(int sock, const char *username, const char *service, const char *rhost, const char *tty) {
    json_object *request = json_object_new_object();
    json_object *type = json_object_new_string("authenticate");
    json_object *user_id = json_object_new_string(username);
    json_object *login_type = json_object_new_string("unknown");
    json_object *target_host = json_object_new_string(rhost);
    json_object *metadata = json_object_new_object();
    json_object *service_obj = json_object_new_string(service);
    json_object *tty_obj = json_object_new_string(tty);
    
    // Determine login type based on service and TTY
    if (strcmp(service, "sshd") == 0) {
        json_object_object_del(request, "login_type");
        json_object_object_add(request, "login_type", json_object_new_string("ssh"));
    } else if (strstr(tty, "tty") != NULL) {
        json_object_object_del(request, "login_type");
        json_object_object_add(request, "login_type", json_object_new_string("console"));
    } else if (strstr(service, "gdm") != NULL || strstr(service, "lightdm") != NULL) {
        json_object_object_del(request, "login_type");
        json_object_object_add(request, "login_type", json_object_new_string("gui"));
    }
    
    // Add metadata
    json_object_object_add(metadata, "service", service_obj);
    json_object_object_add(metadata, "tty", tty_obj);
    json_object_object_add(metadata, "pid", json_object_new_int(getpid()));
    
    // Build request
    json_object_object_add(request, "type", type);
    json_object_object_add(request, "user_id", user_id);
    json_object_object_add(request, "target_host", target_host);
    json_object_object_add(request, "metadata", metadata);
    
    // Convert to string
    const char *request_str = json_object_to_json_string(request);
    size_t request_len = strlen(request_str);
    
    log_pam_message(LOG_DEBUG, "Sending auth request: %s", request_str);
    
    // Send request
    ssize_t sent = send(sock, request_str, request_len, 0);
    if (sent == -1) {
        log_pam_message(LOG_ERR, "Failed to send request: %s", strerror(errno));
        json_object_put(request);
        return -1;
    }
    
    if (sent != (ssize_t)request_len) {
        log_pam_message(LOG_ERR, "Partial send: sent %zd of %zu bytes", sent, request_len);
        json_object_put(request);
        return -1;
    }
    
    json_object_put(request);
    return 0;
}

// Receive authentication response from broker
int receive_auth_response(int sock, char *response, size_t response_size) {
    ssize_t received = recv(sock, response, response_size - 1, 0);
    if (received == -1) {
        log_pam_message(LOG_ERR, "Failed to receive response: %s", strerror(errno));
        return -1;
    }
    
    if (received == 0) {
        log_pam_message(LOG_ERR, "Connection closed by broker");
        return -1;
    }
    
    response[received] = '\0';
    log_pam_message(LOG_DEBUG, "Received response: %s", response);
    
    return 0;
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

// Prompt user for input
int prompt_user(pam_handle_t *pamh, const char *prompt, char *response, size_t response_size) {
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
    
    msg.msg_style = PAM_PROMPT_ECHO_ON;
    msg.msg = prompt;
    
    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Failed to prompt user: %s", pam_strerror(pamh, retval));
        return retval;
    }
    
    if (resp && resp->resp) {
        strncpy(response, resp->resp, response_size - 1);
        response[response_size - 1] = '\0';
        
        // Clean up
        free(resp->resp);
        free(resp);
    } else {
        response[0] = '\0';
    }
    
    return PAM_SUCCESS;
}

// Parse module arguments
static void parse_arguments(int argc, const char **argv) {
    int i;
    
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            debug_enabled = 1;
            log_pam_message(LOG_DEBUG, "Debug mode enabled");
        } else if (strncmp(argv[i], "config=", 7) == 0) {
            strncpy(config_path, argv[i] + 7, sizeof(config_path) - 1);
            config_path[sizeof(config_path) - 1] = '\0';
            log_pam_message(LOG_DEBUG, "Using config file: %s", config_path);
        }
    }
}

// PAM authentication function
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username, *service, *rhost, *tty;
    char response[MAX_BUFFER_SIZE];
    int sock, retval;
    json_object *response_obj, *success_obj, *instructions_obj, *requires_device_obj;
    const char *instructions;
    int success, requires_device;
    
    log_pam_message(LOG_INFO, "OIDC PAM authentication started (version %s)", PAM_MODULE_VERSION);
    
    // Parse module arguments
    parse_arguments(argc, argv);
    
    // Get user information
    retval = get_user_info(pamh, &username, &service, &rhost, &tty);
    if (retval != PAM_SUCCESS) {
        return retval;
    }
    
    log_pam_message(LOG_INFO, "Authenticating user: %s", username);
    
    // Connect to broker
    sock = connect_to_broker(SOCKET_PATH);
    if (sock == -1) {
        log_pam_message(LOG_ERR, "Failed to connect to authentication broker");
        return PAM_AUTHINFO_UNAVAIL;
    }
    
    // Send authentication request
    if (send_auth_request(sock, username, service, rhost, tty) != 0) {
        close(sock);
        return PAM_AUTHINFO_UNAVAIL;
    }
    
    // Receive response
    if (receive_auth_response(sock, response, sizeof(response)) != 0) {
        close(sock);
        return PAM_AUTHINFO_UNAVAIL;
    }
    
    close(sock);
    
    // Parse JSON response
    response_obj = json_tokener_parse(response);
    if (!response_obj) {
        log_pam_message(LOG_ERR, "Failed to parse JSON response");
        return PAM_AUTHINFO_UNAVAIL;
    }
    
    // Check if authentication was successful
    if (!json_object_object_get_ex(response_obj, "success", &success_obj)) {
        log_pam_message(LOG_ERR, "No success field in response");
        json_object_put(response_obj);
        return PAM_AUTHINFO_UNAVAIL;
    }
    
    success = json_object_get_boolean(success_obj);
    
    if (success) {
        log_pam_message(LOG_INFO, "Authentication successful for user: %s", username);
        json_object_put(response_obj);
        return PAM_SUCCESS;
    }
    
    // Check if device authentication is required
    if (json_object_object_get_ex(response_obj, "requires_device", &requires_device_obj)) {
        requires_device = json_object_get_boolean(requires_device_obj);
        
        if (requires_device) {
            // Display instructions to user
            if (json_object_object_get_ex(response_obj, "instructions", &instructions_obj)) {
                instructions = json_object_get_string(instructions_obj);
                display_message(pamh, instructions);
                
                // For device flow, we need to poll for completion
                // This is a simplified implementation - in practice, we'd need
                // to implement proper polling with timeouts
                log_pam_message(LOG_INFO, "Device authentication required for user: %s", username);
                json_object_put(response_obj);
                return PAM_AUTHINFO_UNAVAIL; // For now, require manual retry
            }
        }
    }
    
    log_pam_message(LOG_INFO, "Authentication failed for user: %s", username);
    json_object_put(response_obj);
    return PAM_AUTH_ERR;
}

// PAM credential setting function
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    log_pam_message(LOG_DEBUG, "pam_sm_setcred called with flags: %d", flags);
    
    // Parse arguments
    parse_arguments(argc, argv);
    
    // For OIDC authentication, we don't need to set traditional credentials
    // The broker handles token management
    return PAM_SUCCESS;
}

// PAM account management function
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    int retval;
    
    log_pam_message(LOG_DEBUG, "pam_sm_acct_mgmt called with flags: %d", flags);
    
    // Parse arguments
    parse_arguments(argc, argv);
    
    // Get username
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Failed to get username: %s", pam_strerror(pamh, retval));
        return retval;
    }
    
    log_pam_message(LOG_DEBUG, "Account management check for user: %s", username);
    
    // For OIDC authentication, account management is handled by the identity provider
    // We could add additional checks here if needed
    return PAM_SUCCESS;
}

// PAM session open function
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    int retval;
    
    log_pam_message(LOG_DEBUG, "pam_sm_open_session called with flags: %d", flags);
    
    // Parse arguments
    parse_arguments(argc, argv);
    
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
    parse_arguments(argc, argv);
    
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
    log_pam_message(LOG_DEBUG, "pam_sm_chauthtok called with flags: %d", flags);
    
    // Parse arguments
    parse_arguments(argc, argv);
    
    // OIDC authentication doesn't support password changes through PAM
    // Password changes should be done through the identity provider
    return PAM_AUTHTOK_ERR;
}