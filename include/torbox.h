#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// TorBox device-code authorization, entirely in memory.
bool torbox_start_auth(char *error, size_t error_size);
bool torbox_poll_auth(char *error, size_t error_size);
void torbox_disconnect(void);
bool torbox_connected(void);
bool torbox_auth_pending(void);
const char *torbox_auth_code(void);

// Explicit refresh; never mutates the user's cloud account.
bool torbox_refresh_files(char *error, size_t error_size);
size_t torbox_file_count(void);
const char *torbox_file_name(size_t index);
uint64_t torbox_file_size(size_t index);

// Resolve a selected cloud file into a signed final CDN download URL.
// The caller must never display or persist this URL.
bool torbox_file_url(size_t index, char *url, size_t capacity,
                     char *error, size_t error_size);
