#include "alldebrid_pin.h"

#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RESPONSE_MAX 65536

static char g_pin[64];
static char g_check[256];

static int g_expires_in = 0;
static bool g_pending = false;


/* --------------------------------------------------------- */
/* Small response buffer                                     */
/* --------------------------------------------------------- */

typedef struct {
    char *data;
    size_t size;
    size_t capacity;
    bool overflow;
} ResponseBuffer;


static size_t write_callback(
    char *ptr,
    size_t size,
    size_t nmemb,
    void *userdata
)
{
    ResponseBuffer *buffer =
        (ResponseBuffer *)userdata;

    size_t amount =
        size * nmemb;

    if (
        buffer->size +
        amount +
        1 >
        buffer->capacity
    ) {
        buffer->overflow = true;
        return 0;
    }

    memcpy(
        buffer->data +
        buffer->size,
        ptr,
        amount
    );

    buffer->size += amount;

    buffer->data[
        buffer->size
    ] = '\0';

    return amount;
}


static const char *skip_space(
    const char *p
)
{
    while (
        *p == ' ' ||
        *p == '\t' ||
        *p == '\r' ||
        *p == '\n'
    ) {
        p++;
    }

    return p;
}


/* --------------------------------------------------------- */
/* Tiny JSON helpers                                         */
/* --------------------------------------------------------- */

static bool json_string(
    const char *json,
    const char *key,
    char *output,
    size_t output_size
)
{
    char needle[128];

    snprintf(
        needle,
        sizeof(needle),
        "\"%s\"",
        key
    );

    const char *p =
        strstr(
            json,
            needle
        );

    if (!p)
        return false;

    p += strlen(needle);
    p = skip_space(p);

    if (*p != ':')
        return false;

    p++;
    p = skip_space(p);

    if (*p != '"')
        return false;

    p++;

    size_t out = 0;

    while (
        *p &&
        *p != '"' &&
        out + 1 <
        output_size
    ) {
        if (*p == '\\') {
            p++;

            if (!*p)
                break;

            switch (*p) {
                case '"':
                    output[out++] = '"';
                    break;

                case '\\':
                    output[out++] = '\\';
                    break;

                case '/':
                    output[out++] = '/';
                    break;

                case 'n':
                    output[out++] = '\n';
                    break;

                case 'r':
                    output[out++] = '\r';
                    break;

                case 't':
                    output[out++] = '\t';
                    break;

                default:
                    output[out++] = *p;
                    break;
            }

            p++;
            continue;
        }

        output[out++] =
            *p++;
    }

    output[out] = '\0';

    return true;
}


static bool json_integer(
    const char *json,
    const char *key,
    int *value
)
{
    char needle[128];

    snprintf(
        needle,
        sizeof(needle),
        "\"%s\"",
        key
    );

    const char *p =
        strstr(
            json,
            needle
        );

    if (!p)
        return false;

    p += strlen(needle);
    p = skip_space(p);

    if (*p != ':')
        return false;

    p++;
    p = skip_space(p);

    *value =
        atoi(p);

    return true;
}


static bool json_bool(
    const char *json,
    const char *key,
    bool *value
)
{
    char needle[128];

    snprintf(
        needle,
        sizeof(needle),
        "\"%s\"",
        key
    );

    const char *p =
        strstr(
            json,
            needle
        );

    if (!p)
        return false;

    p += strlen(needle);
    p = skip_space(p);

    if (*p != ':')
        return false;

    p++;
    p = skip_space(p);

    if (
        strncmp(
            p,
            "true",
            4
        ) == 0
    ) {
        *value = true;
        return true;
    }

    if (
        strncmp(
            p,
            "false",
            5
        ) == 0
    ) {
        *value = false;
        return true;
    }

    return false;
}


static bool json_success(
    const char *json
)
{
    char status[32];

    if (
        !json_string(
            json,
            "status",
            status,
            sizeof(status)
        )
    ) {
        return false;
    }

    return
        strcmp(
            status,
            "success"
        ) == 0;
}


/* --------------------------------------------------------- */
/* HTTP                                                      */
/* --------------------------------------------------------- */

static void configure_curl(
    CURL *curl
)
{
    curl_easy_setopt(
        curl,
        CURLOPT_CONNECTTIMEOUT,
        15L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_TIMEOUT,
        30L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_NOSIGNAL,
        1L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTP_VERSION,
        CURL_HTTP_VERSION_1_1
    );

    curl_easy_setopt(
        curl,
        CURLOPT_SSL_VERIFYPEER,
        1L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_SSL_VERIFYHOST,
        2L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_USERAGENT,
        "SwitchDebridDownloader"
    );
}


static bool api_get(
    const char *url,
    char *response,
    size_t response_size,
    long *http_status
)
{
    CURL *curl =
        curl_easy_init();

    if (!curl)
        return false;

    ResponseBuffer buffer = {
        .data = response,
        .size = 0,
        .capacity = response_size,
        .overflow = false
    };

    response[0] = '\0';

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        url
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &buffer
    );

    configure_curl(
        curl
    );

    CURLcode rc =
        curl_easy_perform(
            curl
        );

    *http_status = 0;

    curl_easy_getinfo(
        curl,
        CURLINFO_RESPONSE_CODE,
        http_status
    );

    curl_easy_cleanup(
        curl
    );

    return
        rc == CURLE_OK &&
        !buffer.overflow;
}


static bool api_post(
    const char *url,
    const char *post_data,
    char *response,
    size_t response_size,
    long *http_status
)
{
    CURL *curl =
        curl_easy_init();

    if (!curl)
        return false;

    ResponseBuffer buffer = {
        .data = response,
        .size = 0,
        .capacity = response_size,
        .overflow = false
    };

    response[0] = '\0';

    struct curl_slist *headers =
        NULL;

    headers =
        curl_slist_append(
            headers,
            "Content-Type: application/x-www-form-urlencoded"
        );

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        url
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POST,
        1L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDS,
        post_data
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPHEADER,
        headers
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &buffer
    );

    configure_curl(
        curl
    );

    CURLcode rc =
        curl_easy_perform(
            curl
        );

    *http_status = 0;

    curl_easy_getinfo(
        curl,
        CURLINFO_RESPONSE_CODE,
        http_status
    );

    curl_easy_cleanup(
        curl
    );

    if (headers)
        curl_slist_free_all(
            headers
        );

    return
        rc == CURLE_OK &&
        !buffer.overflow;
}


/* --------------------------------------------------------- */
/* PIN flow                                                  */
/* --------------------------------------------------------- */

void alldebrid_pin_reset(void)
{
    memset(
        g_pin,
        0,
        sizeof(g_pin)
    );

    memset(
        g_check,
        0,
        sizeof(g_check)
    );

    g_expires_in = 0;
    g_pending = false;
}


bool alldebrid_pin_start(
    char *error,
    size_t error_size
)
{
    alldebrid_pin_reset();

    char *response =
        malloc(
            RESPONSE_MAX
        );

    if (!response) {
        snprintf(
            error,
            error_size,
            "Out of memory."
        );

        return false;
    }

    long http_status = 0;

    bool ok =
        api_get(
            "https://api.alldebrid.com/v4.1/pin/get",
            response,
            RESPONSE_MAX,
            &http_status
        );

    if (
        !ok ||
        http_status != 200 ||
        !json_success(response)
    ) {
        char code[128] = {0};
        char message[256] = {0};

        json_string(
            response,
            "code",
            code,
            sizeof(code)
        );

        json_string(
            response,
            "message",
            message,
            sizeof(message)
        );

        snprintf(
            error,
            error_size,
            "PIN request failed. HTTP %ld. %s%s%s",
            http_status,
            code,
            message[0] ? ": " : "",
            message
        );

        free(response);
        return false;
    }

    bool parsed =
        json_string(
            response,
            "pin",
            g_pin,
            sizeof(g_pin)
        ) &&

        json_string(
            response,
            "check",
            g_check,
            sizeof(g_check)
        );

    json_integer(
        response,
        "expires_in",
        &g_expires_in
    );

    free(response);

    if (!parsed) {
        snprintf(
            error,
            error_size,
            "Invalid PIN response."
        );

        alldebrid_pin_reset();

        return false;
    }

    g_pending = true;

    return true;
}


bool alldebrid_pin_check(
    bool *activated,
    char *apikey,
    size_t apikey_size,
    char *error,
    size_t error_size
)
{
    if (activated)
        *activated = false;

    if (
        apikey &&
        apikey_size
    ) {
        apikey[0] = '\0';
    }

    if (!g_pending) {
        snprintf(
            error,
            error_size,
            "No PIN authentication is active."
        );

        return false;
    }

    char post_data[512];

    snprintf(
        post_data,
        sizeof(post_data),
        "pin=%s&check=%s",
        g_pin,
        g_check
    );

    char *response =
        malloc(
            RESPONSE_MAX
        );

    if (!response) {
        snprintf(
            error,
            error_size,
            "Out of memory."
        );

        return false;
    }

    long http_status = 0;

    bool ok =
        api_post(
            "https://api.alldebrid.com/v4/pin/check",
            post_data,
            response,
            RESPONSE_MAX,
            &http_status
        );

    if (
        !ok ||
        http_status != 200 ||
        !json_success(response)
    ) {
        char code[128] = {0};
        char message[256] = {0};

        json_string(
            response,
            "code",
            code,
            sizeof(code)
        );

        json_string(
            response,
            "message",
            message,
            sizeof(message)
        );

        snprintf(
            error,
            error_size,
            "PIN check failed. HTTP %ld. %s%s%s",
            http_status,
            code,
            message[0] ? ": " : "",
            message
        );

        free(response);

        alldebrid_pin_reset();

        return false;
    }

    bool is_activated = false;

    if (
        !json_bool(
            response,
            "activated",
            &is_activated
        )
    ) {
        snprintf(
            error,
            error_size,
            "Invalid PIN status response."
        );

        free(response);

        return false;
    }

    json_integer(
        response,
        "expires_in",
        &g_expires_in
    );

    if (!is_activated) {
        free(response);

        if (activated)
            *activated = false;

        return true;
    }

    if (
        !apikey ||
        !apikey_size ||
        !json_string(
            response,
            "apikey",
            apikey,
            apikey_size
        ) ||
        !apikey[0]
    ) {
        snprintf(
            error,
            error_size,
            "PIN approved but API key was missing."
        );

        free(response);

        return false;
    }

    free(response);

    if (activated)
        *activated = true;

    g_pending = false;

    return true;
}


bool alldebrid_pin_pending(void)
{
    return g_pending;
}


const char *alldebrid_pin_code(void)
{
    return g_pin;
}


int alldebrid_pin_expires(void)
{
    return g_expires_in;
}
