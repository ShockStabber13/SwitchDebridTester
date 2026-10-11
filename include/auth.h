#pragma once

#include <stdbool.h>
#include <stddef.h>

bool remote_auth_ensure_password(void);

bool remote_auth_verify(
    const char *password
);

bool remote_auth_create_session(
    const char *client_ip,
    char *token_out,
    size_t token_out_size
);

bool remote_auth_session_valid(
    const char *token,
    const char *client_ip
);

void remote_auth_revoke_session(
    const char *token,
    const char *client_ip
);

void remote_auth_revoke_all(void);
