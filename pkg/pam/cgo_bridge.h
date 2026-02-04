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

// PAM module name for logging
#define PAM_MODULE_NAME "pam_oidc"

// Maximum buffer sizes
#define MAX_RESPONSE_SIZE 8192
#define MAX_SOCKET_PATH 108

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
