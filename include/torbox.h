#pragma once

#include <stdbool.h>
#include <stddef.h>

// TorBox API key remains only in RAM. Never write to config.ini or logs.
bool torbox_set_api_key(const char *key);
void torbox_clear_api_key(void);
bool torbox_has_api_key(void);

// Resolve a torrent or WebDL file to the final signed CDN HTTPS URL.
// torrent_or_webdl_id and file_id must be numeric identifiers.
// This calls only api.torbox.app and does not download any file data.
bool torbox_resolve_download(
    bool webdl,
    const char *torrent_or_webdl_id,
    const char *file_id,
    char *cdn_url,
    size_t cdn_url_size,
    char *error,
    size_t error_size);
