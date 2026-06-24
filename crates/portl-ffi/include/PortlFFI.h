#ifndef PORTL_FFI_H
#define PORTL_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PortlClient PortlClient;
typedef struct PortlShell PortlShell;

typedef void (*portl_shell_event_callback)(
    void *context,
    uint32_t event,
    const uint8_t *data,
    uintptr_t data_len,
    int32_t code,
    const char *message
);

enum {
    PORTL_SHELL_EVENT_STDOUT = 1,
    PORTL_SHELL_EVENT_STDERR = 2,
    PORTL_SHELL_EVENT_EXIT = 3,
    PORTL_SHELL_EVENT_ERROR = 4,
    PORTL_SHELL_EVENT_CLOSED = 5,
};

uint32_t portl_ffi_abi_version(void);
const char *portl_ffi_version(void);
bool portl_ffi_iroh_quic_available(void);
const char *portl_last_error(void);
void portl_string_free(char *value);

int32_t portl_identity_generate(uint8_t *identity_seed32_out);

PortlClient *portl_client_new(const uint8_t *identity_seed32);
PortlClient *portl_client_new_with_stores(
    const uint8_t *identity_seed32,
    const char *peer_store_path,
    const char *ticket_store_path
);
void portl_client_free(PortlClient *client);
char *portl_client_endpoint_id(const PortlClient *client);
char *portl_client_save_ticket(
    const PortlClient *client,
    const char *label,
    const char *ticket
);
char *portl_client_import_session_share_envelope_json(
    const PortlClient *client,
    const char *label,
    const char *envelope_json
);
char *portl_client_accept_session_share_code(
    const PortlClient *client,
    const char *code,
    const char *label,
    const char *rendezvous_url,
    uint64_t timeout_millis
);
char *portl_client_accept_peer_invite(
    const PortlClient *client,
    const char *code,
    const char *local_label,
    uint64_t timeout_millis
);

int32_t portl_shell_open_ticket(
    PortlClient *client,
    const char *ticket,
    const char *term,
    uint16_t cols,
    uint16_t rows,
    portl_shell_event_callback callback,
    void *callback_context,
    PortlShell **shell_out
);
int32_t portl_shell_open_target(
    PortlClient *client,
    const char *target,
    const char *term,
    uint16_t cols,
    uint16_t rows,
    portl_shell_event_callback callback,
    void *callback_context,
    PortlShell **shell_out
);
int32_t portl_session_attach_ticket(
    PortlClient *client,
    const char *ticket,
    const char *provider,
    const char *session_name,
    const char *term,
    uint16_t cols,
    uint16_t rows,
    portl_shell_event_callback callback,
    void *callback_context,
    PortlShell **shell_out
);
int32_t portl_session_attach_target(
    PortlClient *client,
    const char *target,
    const char *provider,
    const char *session_name,
    const char *term,
    uint16_t cols,
    uint16_t rows,
    portl_shell_event_callback callback,
    void *callback_context,
    PortlShell **shell_out
);
int32_t portl_shell_write(PortlShell *shell, const uint8_t *data, uintptr_t data_len);
int32_t portl_shell_resize(PortlShell *shell, uint16_t cols, uint16_t rows);
bool portl_shell_is_closed(const PortlShell *shell);
void portl_shell_close(PortlShell *shell);

#ifdef __cplusplus
}
#endif

#endif
