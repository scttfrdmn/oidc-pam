#ifndef CGO_BRIDGE_H
#define CGO_BRIDGE_H

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

// PAM module name and version
#define PAM_MODULE_NAME "pam_oidc"
#define PAM_MODULE_VERSION "0.1.0"

// Maximum buffer sizes
#define MAX_BUFFER_SIZE 8192
#define MAX_RESPONSE_SIZE 8192
#define MAX_SOCKET_PATH 108

// Default socket path for OIDC broker
#define SOCKET_PATH "/var/run/oidc-auth-broker.sock"

// Function prototypes
void log_pam_message(int priority, const char *format, ...);
void log_pam_message_string(int priority, const char *message);
int connect_to_broker(const char *socket_path);
int get_user_info(pam_handle_t *pamh, const char **username, const char **service, const char **rhost, const char **tty);
int send_auth_request(int sock, const char *username, const char *service, const char *rhost, const char *tty);
int receive_auth_response(int sock, char *response, size_t response_size);
int display_message(pam_handle_t *pamh, const char *message);
int prompt_user(pam_handle_t *pamh, const char *prompt, char *response, size_t response_size);

#endif // CGO_BRIDGE_H
