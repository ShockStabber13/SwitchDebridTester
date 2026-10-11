#include "torbox.h"
#include <curl/curl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TB_URL "https://api.torbox.app/v1/api/"
#define TB_MAX_FILES 96
#define TB_HTTP_LIMIT (2 * 1024 * 1024)
#define TB_MAX_TOKENS 16384

typedef struct {
    int start, end, next;
    char type;
} JTok;

typedef struct {
    char name[320];
    char parent[160];
    char item_id[32];
    char file_id[32];
    uint64_t size;
    bool webdl;
} TBFile;

static char g_access_token[1024];
static char g_device_code[256];
static char g_pair_code[64];
static time_t g_auth_deadline;
static time_t g_next_check;
static int g_check_interval = 5;
static TBFile g_files[TB_MAX_FILES];
static size_t g_file_count;

static void clear_secret(char *secret, size_t size)
{
    volatile char *dst = (volatile char *)secret;
    for (size_t i = 0; i < size; ++i) dst[i] = 0;
}

bool torbox_connected(void) { return g_access_token[0] != '\0'; }
bool torbox_auth_pending(void) { return g_device_code[0] != '\0'; }
const char *torbox_auth_code(void) { return g_pair_code; }
size_t torbox_file_count(void) { return g_file_count; }
const char *torbox_file_name(size_t i) {
    return i < g_file_count ? g_files[i].name : "";
}
uint64_t torbox_file_size(size_t i) {
    return i < g_file_count ? g_files[i].size : 0;
}

void torbox_disconnect(void)
{
    clear_secret(g_access_token, sizeof(g_access_token));
    clear_secret(g_device_code, sizeof(g_device_code));
    memset(g_pair_code, 0, sizeof(g_pair_code));
    memset(g_files, 0, sizeof(g_files));
    g_file_count = 0;
    g_auth_deadline = 0;
    g_next_check = 0;
}

typedef struct {
    char *body;
    size_t len, cap;
} TBResponse;

static size_t tb_write(char *data, size_t size, size_t count, void *arg)
{
    TBResponse *r = (TBResponse *)arg;
    if (size && count > SIZE_MAX / size) return 0;
    const size_t amount = size * count;
    if (amount >= r->cap - r->len) return 0;
    memcpy(r->body + r->len, data, amount);
    r->len += amount;
    r->body[r->len] = 0;
    return amount;
}

static bool tb_request(const char *path, const char *post_json, bool authenticated,
                       TBResponse *out, long *http_status, char *error, size_t error_size)
{
    memset(out, 0, sizeof(*out));
    out->body = (char *)malloc(TB_HTTP_LIMIT);
    if (!out->body) {
        snprintf(error, error_size, "Not enough memory for TorBox API response.");
        return false;
    }
    out->cap = TB_HTTP_LIMIT;
    out->body[0] = 0;
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(out->body);
        out->body = NULL;
        snprintf(error, error_size, "TorBox curl initialization failed.");
        return false;
    }
    char url[512];
    const int n = snprintf(url, sizeof(url), "%s%s", TB_URL, path);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        curl_easy_cleanup(curl);
        free(out->body);
        out->body = NULL;
        snprintf(error, error_size, "TorBox request is too long.");
        return false;
    }
    struct curl_slist *headers = NULL;
    char bearer[1200] = {0};
    if (authenticated) {
        if (!torbox_connected()) {
            curl_easy_cleanup(curl);
            free(out->body);
            out->body = NULL;
            snprintf(error, error_size, "Connect TorBox first.");
            return false;
        }
        snprintf(bearer, sizeof(bearer), "Authorization: Bearer %s", g_access_token);
        headers = curl_slist_append(headers, bearer);
    }
    if (post_json) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_json);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_json));
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SwitchDebridTester/1.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tb_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    const CURLcode rc = curl_easy_perform(curl);
    *http_status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    clear_secret(bearer, sizeof(bearer));
    if (rc != CURLE_OK || *http_status != 200) {
        snprintf(error, error_size, "TorBox API HTTP %ld, curl %d.",
                 *http_status, (int)rc);
        free(out->body);
        out->body = NULL;
        return false;
    }
    return true;
}

static void json_skip(const char **p)
{
    while (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n') ++*p;
}

static int json_parse_value(const char **p, const char *begin, JTok *t,
                            int *count, int depth)
{
    if (depth > 32 || *count >= TB_MAX_TOKENS) return -1;
    json_skip(p);
    const char kind = **p;
    if (!kind) return -1;
    const int index = (*count)++;
    t[index].start = (int)(*p - begin);
    t[index].type = kind;
    if (kind == '"' ) {
        ++*p;
        while (**p) {
            if (**p == '\\') {
                ++*p;
                if (!**p) return -1;
                ++*p;
                continue;
            }
            if (**p == '"') break;
            ++*p;
        }
        if (**p != '"') return -1;
        ++*p;
    } else if (kind == '{' || kind == '[') {
        const char end = kind == '{' ? '}' : ']';
        ++*p;
        json_skip(p);
        if (**p != end) {
            for (;;) {
                if (kind == '{') {
                    if (**p != '"' || json_parse_value(p, begin, t, count, depth+1) < 0)
                        return -1;
                    json_skip(p);
                    if (**p != ':') return -1;
                    ++*p;
                }
                if (json_parse_value(p, begin, t, count, depth+1) < 0) return -1;
                json_skip(p);
                if (**p == end) break;
                if (**p != ',') return -1;
                ++*p;
                json_skip(p);
            }
        }
        ++*p;
    } else {
        // Primitive: number, true, false, null.
        while (**p && **p != ',' && **p != '}' && **p != ']' &&
               **p != '\r' && **p != '\n' && **p != ' ' && **p != '\t')
            ++*p;
        if (t[index].start == (int)(*p - begin)) return -1;
    }
    t[index].end = (int)(*p - begin);
    t[index].next = *count;
    return index;
}

static int json_read(const char *body, JTok *tokens)
{
    const char *p = body;
    int count = 0;
    const int root = json_parse_value(&p, body, tokens, &count, 0);
    json_skip(&p);
    if (root < 0 || *p) return -1;
    return count;
}

static bool json_key_equals(const char *body, const JTok *token, const char *key)
{
    const size_t len = strlen(key);
    return token->type == '"' &&
           token->end - token->start == (int)len + 2 &&
           memcmp(body + token->start + 1, key, len) == 0;
}

static int json_field(const char *body, const JTok *tokens, int object, const char *field)
{
    if (object < 0 || tokens[object].type != '{') return -1;
    for (int at = object + 1; at < tokens[object].next;) {
        const int val = at + 1;
        if (val >= tokens[object].next) return -1;
        if (json_key_equals(body, &tokens[at], field)) return val;
        at = tokens[val].next;
    }
    return -1;
}

static bool json_string(const char *body, const JTok *t, int index,
                        char *dst, size_t cap)
{
    if (index < 0 || !dst || cap < 2 || t[index].type != '"') return false;
    const char *p = body + t[index].start + 1;
    const char *end = body + t[index].end - 1;
    size_t n = 0;
    while (p < end && n + 1 < cap) {
        unsigned char c = (unsigned char)*p++;
        if (c == '\\' && p < end) {
            c = (unsigned char)*p++;
            if (c == 'u') {
                // JSON Unicode escapes are harmlessly replaced in display
                // labels; raw UTF-8 filenames are preserved unchanged.
                if (end - p < 4) return false;
                p += 4; c = '?';
            } else if (c == 'n' || c == 'r' || c == 't') {
                c = ' ';
            }
        }
        dst[n++] = (char)c;
    }
    dst[n] = '\0';
    return p == end;
}

static bool json_number(const char *body, const JTok *t, int index,
                        char *dst, size_t cap)
{
    if (index < 0 || cap < 2) return false;
    if (t[index].type == '"') return json_string(body, t, index, dst, cap);
    const int len = t[index].end - t[index].start;
    if (len <= 0 || (size_t)len >= cap) return false;
    memcpy(dst, body + t[index].start, (size_t)len);
    dst[len] = '\0';
    return true;
}
static bool json_boolean(const char *body, const JTok *t, int index)
{
    return index >= 0 && t[index].type == 't' &&
           strncmp(body + t[index].start, "true", 4) == 0;
}
static bool json_ok(const char *body, const JTok *t)
{
    return json_boolean(body, t, json_field(body, t, 0, "success"));
}
static bool id_numeric(const char *id)
{
    if (!id[0]) return false;
    for (const char *p = id; *p; ++p) if (*p < '0' || *p > '9') return false;
    return true;
}
static bool secret_valid(const char *s)
{
    if (!s || !s[0]) return false;
    for (; *s; ++s) {
        const unsigned char c = (unsigned char)*s;
        if (!isalnum(c) && c != '-' && c != '_') return false;
    }
    return true;
}

bool torbox_start_auth(char *error, size_t error_size)
{
    torbox_disconnect();
    TBResponse response;
    long status;
    if (!tb_request("user/auth/device/start?app=SwitchDebridTester",
                    NULL, false, &response, &status, error, error_size))
        return false;
    JTok *t = (JTok *)calloc(TB_MAX_TOKENS, sizeof(JTok));
    if (!t) {
        free(response.body);
        snprintf(error, error_size, "Not enough memory.");
        return false;
    }
    bool ok = false;
    if (json_read(response.body, t) > 0 && json_ok(response.body, t)) {
        const int data = json_field(response.body, t, 0, "data");
        char interval[32] = {0};
        json_number(response.body, t, json_field(response.body, t, data, "interval"),
                    interval, sizeof(interval));
        g_check_interval = atoi(interval);
        if (g_check_interval < 3) g_check_interval = 3;
        if (g_check_interval > 30) g_check_interval = 30;
        ok = json_string(response.body, t,
                         json_field(response.body, t, data, "device_code"),
                         g_device_code, sizeof(g_device_code)) &&
             json_string(response.body, t,
                         json_field(response.body, t, data, "code"),
                         g_pair_code, sizeof(g_pair_code)) &&
             secret_valid(g_device_code) && secret_valid(g_pair_code);
    }
    free(t);
    free(response.body);
    if (!ok) {
        torbox_disconnect();
        snprintf(error, error_size, "TorBox device authorization did not return a valid code.");
        return false;
    }
    g_auth_deadline = time(NULL) + 600;
    g_next_check = 0;
    return true;
}

bool torbox_poll_auth(char *error, size_t error_size)
{
    if (!torbox_auth_pending() || time(NULL) >= g_auth_deadline) {
        snprintf(error, error_size, "TorBox code expired. Connect again.");
        return false;
    }
    if (time(NULL) < g_next_check) {
        snprintf(error, error_size, "Wait %ld more seconds before checking.",
                 (long)(g_next_check - time(NULL)));
        return false;
    }
    g_next_check = time(NULL) + g_check_interval;
    char payload[400];
    snprintf(payload, sizeof(payload), "{\"device_code\":\"%s\"}", g_device_code);
    TBResponse response;
    long status;
    if (!tb_request("user/auth/device/token", payload, false, &response,
                    &status, error, error_size)) return false;
    JTok *t = (JTok *)calloc(TB_MAX_TOKENS, sizeof(JTok));
    if (!t) {
        free(response.body);
        snprintf(error, error_size, "Not enough memory.");
        return false;
    }
    bool ok = false;
    if (json_read(response.body, t) > 0 && json_ok(response.body, t)) {
        const int data = json_field(response.body, t, 0, "data");
        ok = json_string(response.body, t,
                         json_field(response.body, t, data, "access_token"),
                         g_access_token, sizeof(g_access_token)) &&
             secret_valid(g_access_token);
    }
    free(t);
    free(response.body);
    if (!ok) {
        snprintf(error, error_size, "TorBox authorization pending. Approve the code first.");
        return false;
    }
    clear_secret(g_device_code, sizeof(g_device_code));
    memset(g_pair_code, 0, sizeof(g_pair_code));
    g_auth_deadline = 0;
    return true;
}

static void parse_files_from_rows(const char *body, const JTok *t,
                                  int rows, bool webdl)
{
    if (rows < 0 || t[rows].type != '[') return;
    for (int item = rows + 1; item < t[rows].next && g_file_count < TB_MAX_FILES;
         item = t[item].next) {
        if (t[item].type != '{') continue;
        char item_id[32] = {0}, parent[160] = {0};
        json_number(body, t, json_field(body, t, item, "id"), item_id, sizeof(item_id));
        if (!id_numeric(item_id)) continue;
        json_string(body, t, json_field(body, t, item, "name"),
                    parent, sizeof(parent));
        if (!parent[0]) snprintf(parent, sizeof(parent), "%s %s",
                                  webdl ? "WebDL" : "Torrent", item_id);
        const int finished = json_field(body, t, item, "download_finished");
        const int cached = json_field(body, t, item, "cached");
        const int present = json_field(body, t, item, "download_present");
        bool ready = json_boolean(body, t, finished) ||
                     (!webdl && json_boolean(body, t, cached));
        if (webdl && present >= 0 && !json_boolean(body, t, present)) ready = false;
        if (!ready) continue;
        const int files = json_field(body, t, item, "files");
        if (files < 0 || t[files].type != '[') continue;
        for (int entry = files + 1; entry < t[files].next &&
                                  g_file_count < TB_MAX_FILES;
             entry = t[entry].next) {
            if (t[entry].type != '{') continue;
            TBFile candidate = {0};
            if (!json_number(body, t, json_field(body,t,entry,"file_id"),
                             candidate.file_id, sizeof(candidate.file_id)))
                json_number(body, t, json_field(body,t,entry,"id"),
                            candidate.file_id, sizeof(candidate.file_id));
            if (!id_numeric(candidate.file_id)) continue;
            if (!json_string(body, t, json_field(body,t,entry,"name"),
                             candidate.name, sizeof(candidate.name)))
                json_string(body, t, json_field(body,t,entry,"path"),
                            candidate.name, sizeof(candidate.name));
            if (!candidate.name[0]) continue;
            char raw_size[32] = {0};
            json_number(body, t, json_field(body,t,entry,"size"), raw_size, sizeof(raw_size));
            candidate.size = strtoull(raw_size, NULL, 10);
            if (candidate.size < (64ULL * 1024 * 1024)) continue;
            memcpy(candidate.item_id, item_id, sizeof(candidate.item_id));
            memcpy(candidate.parent, parent, sizeof(candidate.parent));
            candidate.webdl = webdl;
            g_files[g_file_count++] = candidate;
        }
    }
}

static bool load_one_list(const char *endpoint, bool webdl, char *error, size_t error_size)
{
    TBResponse response;
    long status;
    if (!tb_request(endpoint, NULL, true, &response, &status, error, error_size))
        return false;
    JTok *t = (JTok *)calloc(TB_MAX_TOKENS, sizeof(JTok));
    if (!t) {
        free(response.body);
        snprintf(error, error_size, "Not enough memory for cloud list.");
        return false;
    }
    const bool ok = json_read(response.body, t) > 0 && json_ok(response.body, t);
    if (ok) {
        const int data = json_field(response.body, t, 0, "data");
        if (data >= 0 && t[data].type == '[')
            parse_files_from_rows(response.body, t, data, webdl);
        else if (data >= 0 && t[data].type == '{') {
            const int rows = json_field(response.body,t,data,webdl?"webdl":"torrents");
            if (rows >= 0) parse_files_from_rows(response.body,t,rows,webdl);
        }
    }
    free(t);
    free(response.body);
    if (!ok)
        snprintf(error, error_size, "TorBox rejected the cloud file list.");
    return ok;
}

bool torbox_refresh_files(char *error, size_t error_size)
{
    if (!torbox_connected()) {
        snprintf(error, error_size, "Connect TorBox first.");
        return false;
    }
    memset(g_files, 0, sizeof(g_files));
    g_file_count = 0;
    char torrent_error[180] = {0}, webdl_error[180] = {0};
    const bool torrents = load_one_list("torrents/mylist?limit=100", false,
                                        torrent_error, sizeof(torrent_error));
    const bool webdl = load_one_list("webdl/mylist?limit=100", true,
                                     webdl_error, sizeof(webdl_error));
    if (!torrents && !webdl) {
        snprintf(error,error_size,"TorBox lists failed: %.110s; %.110s",
                 torrent_error,webdl_error);
        return false;
    }
    if (!torrents || !webdl) {
        snprintf(error,error_size,"Partial TorBox list: %.90s %.90s",
                 torrent_error, webdl_error);
    }
    return true;
}

static bool final_url_safe(const char *url)
{
    if (strncmp(url,"https://",8) != 0 || strlen(url) > 8191) return false;
    const char *host = url + 8;
    const char *end = strpbrk(host, "/?#");
    if (!end) end = host + strlen(host);
    if (host == end) return false;
    for (const char *p = host; p < end; ++p)
        if (*p == '@' || *p == ':' || *p == '\\') return false;
    for (const unsigned char *p = (const unsigned char *)url; *p; ++p)
        if (*p < 32 || *p == 127 || *p == '\\') return false;
    return true;
}

bool torbox_file_url(size_t index, char *url, size_t cap,
                     char *error, size_t error_size)
{
    if (!url || !cap) return false;
    url[0] = '\0';
    if (!torbox_connected() || index >= g_file_count) {
        snprintf(error, error_size, "Choose a file from your TorBox account.");
        return false;
    }
    const TBFile *file = &g_files[index];
    // requestdl requires a token query argument. Never follow redirects
    // or log this URL; only return a validated HTTPS CDN link in RAM.
    CURL *easy = curl_easy_init();
    if (!easy) {
        snprintf(error,error_size,"Cannot initialize TorBox link request.");
        return false;
    }
    char *encoded = curl_easy_escape(easy, g_access_token, 0);
    if (!encoded) {
        curl_easy_cleanup(easy);
        snprintf(error,error_size,"Cannot encode TorBox authorization.");
        return false;
    }
    char path[1600];
    const int n = snprintf(path,sizeof(path),
        "%s/requestdl?token=%s&%s=%s&file_id=%s",
        file->webdl ? "webdl" : "torrents",encoded,
        file->webdl ? "web_id" : "torrent_id", file->item_id, file->file_id);
    curl_free(encoded);
    curl_easy_cleanup(easy);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        snprintf(error,error_size,"TorBox request is too long.");
        return false;
    }
    TBResponse response;
    long status;
    const bool received = tb_request(path,NULL,true,&response,&status,error,error_size);
    memset(path,0,sizeof(path));
    if (!received) return false;
    JTok *t = (JTok *)calloc(TB_MAX_TOKENS,sizeof(JTok));
    if (!t) {
        free(response.body);
        snprintf(error,error_size,"Not enough memory.");
        return false;
    }
    bool ok = false;
    if (json_read(response.body,t) > 0 && json_ok(response.body,t)) {
        ok = json_string(response.body,t,json_field(response.body,t,0,"data"),url,cap) &&
             final_url_safe(url);
    }
    free(t);
    free(response.body);
    if (!ok) {
        url[0] = '\0';
        snprintf(error,error_size,"TorBox did not return a valid CDN link.");
    }
    return ok;
}
