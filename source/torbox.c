#include "torbox.h"

#include <curl/curl.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_torbox_key[1024];

void torbox_clear_api_key(void)
{
    volatile unsigned char *p = (volatile unsigned char *)g_torbox_key;
    for (size_t i = 0; i < sizeof(g_torbox_key); ++i) p[i] = 0;
}

bool torbox_has_api_key(void)
{
    return g_torbox_key[0] != '\0';
}

bool torbox_set_api_key(const char *key)
{
    const size_t len = key ? strlen(key) : 0;
    if (len < 8 || len >= sizeof(g_torbox_key)) return false;
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = (unsigned char)key[i];
        if (c <= 32 || c == 127) return false;
    }
    torbox_clear_api_key();
    memcpy(g_torbox_key, key, len);
    g_torbox_key[len] = '\0';
    return true;
}

typedef struct {
    char body[8192];
    size_t len;
} TorboxResponse;

static size_t receive_response(char *data, size_t size, size_t count,
                               void *context)
{
    TorboxResponse *r = (TorboxResponse *)context;
    if (size && count > SIZE_MAX / size) return 0;
    const size_t n = size * count;
    if (n >= sizeof(r->body) - r->len) return 0;
    memcpy(r->body + r->len, data, n);
    r->len += n;
    r->body[r->len] = '\0';
    return n;
}

static bool numeric_id(const char *value)
{
    if (!value || !value[0] || strlen(value) > 32) return false;
    for (const char *p = value; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
    }
    return true;
}

static const char *skip_space(const char *p)
{
    while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') ++p;
    return p;
}

static bool torbox_success(const char *json)
{
    const char *p = strstr(json, "\"success\"");
    if (!p) return false;
    p = strchr(p + 9, ':');
    if (!p) return false;
    return strncmp(skip_space(p + 1), "true", 4) == 0;
}

static int hexdigit(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

// TorBox normally replies with a 302 when redirect=true. Also accept
// its documented JSON response containing a string-valued "data".
static bool parse_json_url(const char *json, char *out, size_t cap)
{
    if (!torbox_success(json)) return false;
    const char *p = strstr(json, "\"data\"");
    if (!p) return false;
    p = strchr(p + 6, ':');
    if (!p) return false;
    p = skip_space(p + 1);
    if (*p++ != '"') return false;
    size_t n = 0;
    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p++;
        if (c == '\\') {
            c = (unsigned char)*p++;
            if (!c) return false;
            switch (c) {
                case '/': case '\\': case '"': break;
                case 'u': {
                    unsigned value = 0;
                    for (unsigned i = 0; i < 4; ++i) {
                        if (!*p) return false;
                        const int h = hexdigit(*p++);
                        if (h < 0) return false;
                        value = (value << 4) | (unsigned)h;
                    }
                    if (!value || value > 127) return false;
                    c = (unsigned char)value;
                    break;
                }
                default: return false;
            }
        }
        if (n + 1 >= cap) return false;
        out[n++] = (char)c;
    }
    if (*p != '"' || n == 0) return false;
    out[n] = '\0';
    return true;
}

static bool safe_https_url(const char *url)
{
    if (strncmp(url, "https://", 8) != 0 || strlen(url) > 8191)
        return false;
    const char *host = url + 8;
    const char *end = strpbrk(host, "/?#");
    if (!end) end = host + strlen(host);
    if (end == host) return false;
    for (const char *p = host; p < end; ++p) {
        if (*p == '@' || *p == ':' || *p == '\\') return false;
    }
    const size_t len = (size_t)(end - host);
    if ((len == 9 && strncmp(host, "localhost", 9) == 0) ||
        (len >= 4 && strncmp(host, "127.", 4) == 0) ||
        (len >= 8 && strncmp(host, "192.168.", 8) == 0) ||
        (len >= 3 && strncmp(host, "10.", 3) == 0))
        return false;
    for (const unsigned char *p = (const unsigned char *)url; *p; ++p) {
        if (*p < 32 || *p == 127 || *p == '\\') return false;
    }
    return true;
}

bool torbox_resolve_download(
    bool webdl, const char *torrent_or_webdl_id, const char *file_id,
    char *cdn_url, size_t cdn_url_size, char *error, size_t error_size)
{
    if (cdn_url && cdn_url_size) cdn_url[0] = '\0';
    if (error && error_size) error[0] = '\0';
    if (!error || !error_size || !cdn_url || cdn_url_size < 256)
        return false;
    if (!torbox_has_api_key()) {
        snprintf(error, error_size, "Connect TorBox first.");
        return false;
    }
    if (!numeric_id(torrent_or_webdl_id) || !numeric_id(file_id)) {
        snprintf(error, error_size, "Torrent/WebDL ID and file ID must be numbers.");
        return false;
    }
    CURL *curl = curl_easy_init();
    if (!curl) {
        snprintf(error, error_size, "Cannot initialize TorBox HTTPS.");
        return false;
    }
    char *encoded = curl_easy_escape(curl, g_torbox_key, 0);
    if (!encoded) {
        curl_easy_cleanup(curl);
        snprintf(error, error_size, "Cannot encode TorBox authorization.");
        return false;
    }
    char request_url[2048];
    const int request_len = snprintf(
        request_url, sizeof(request_url),
        "https://api.torbox.app/v1/api/%s/requestdl"
        "?token=%s&%s=%s&file_id=%s&redirect=true",
        webdl ? "webdl" : "torrents", encoded,
        webdl ? "web_id" : "torrent_id", torrent_or_webdl_id, file_id);
    curl_free(encoded);
    if (request_len < 0 || (size_t)request_len >= sizeof(request_url)) {
        curl_easy_cleanup(curl);
        snprintf(error, error_size, "TorBox authorization is too long.");
        return false;
    }

    char authorization[1200];
    snprintf(authorization, sizeof(authorization),
             "Authorization: Bearer %s", g_torbox_key);
    struct curl_slist *headers =
        curl_slist_append(NULL, authorization);
    // Do not follow the redirect with a token-bearing API request.
    TorboxResponse response = {{0}, 0};
    curl_easy_setopt(curl, CURLOPT_URL, request_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SwitchDebridTester/1.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    const CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc == CURLE_OK &&
        (status == 301 || status == 302 || status == 303 ||
         status == 307 || status == 308)) {
        char *redirect = NULL;
        curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect);
        if (redirect && safe_https_url(redirect) &&
            strlen(redirect) < cdn_url_size)
            snprintf(cdn_url, cdn_url_size, "%s", redirect);
    } else if (rc == CURLE_OK && status == 200) {
        char parsed[8192] = {0};
        if (parse_json_url(response.body, parsed, sizeof(parsed)) &&
            safe_https_url(parsed) &&
            strlen(parsed) < cdn_url_size)
            snprintf(cdn_url, cdn_url_size, "%s", parsed);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    memset(authorization, 0, sizeof(authorization));
    memset(request_url, 0, sizeof(request_url));

    if (!cdn_url[0]) {
        snprintf(error, error_size,
                 "TorBox link unavailable (HTTP %ld, CURL %d). "
                 "Check account, ID and file ID.", status, (int)rc);
        return false;
    }
    return true;
}
