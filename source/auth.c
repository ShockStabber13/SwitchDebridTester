#include "auth.h"

#include <switch.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define AUTH_DIR \
    "sdmc:/config/SwitchDebridDownloader"

#define AUTH_FILE \
    "sdmc:/config/SwitchDebridDownloader/auth.dat"

#define AUTH_MAGIC "SDDAUTH1"
#define AUTH_MAGIC_SIZE 8

#define AUTH_VERSION 1
#define AUTH_ITERATIONS 100000

#define SALT_SIZE 16
#define HASH_SIZE 32

#define MAX_SESSIONS 8
#define SESSION_RANDOM_SIZE 32
#define SESSION_TOKEN_SIZE 65


typedef struct {
    bool used;
    char token[SESSION_TOKEN_SIZE];
    char ip[64];
} AuthSession;


static bool g_loaded = false;

static u32 g_iterations =
    AUTH_ITERATIONS;

static u8 g_salt[SALT_SIZE];
static u8 g_hash[HASH_SIZE];

static AuthSession
    g_sessions[MAX_SESSIONS];

static unsigned
    g_next_session = 0;


/* ========================================================= */
/* Memory                                                    */
/* ========================================================= */

static void secure_zero(
    void *ptr,
    size_t size
)
{
    volatile u8 *p =
        (volatile u8 *)ptr;

    while (size--)
        *p++ = 0;
}


static bool constant_equal(
    const u8 *a,
    const u8 *b,
    size_t size
)
{
    u8 diff = 0;

    for (
        size_t i = 0;
        i < size;
        i++
    ) {
        diff |=
            a[i] ^ b[i];
    }

    return diff == 0;
}


/* ========================================================= */
/* Random                                                    */
/* ========================================================= */

static bool secure_random(
    void *output,
    size_t size
)
{
    Result rc =
        csrngInitialize();

    if (R_FAILED(rc))
        return false;

    rc =
        csrngGetRandomBytes(
            output,
            size
        );

    csrngExit();

    return R_SUCCEEDED(rc);
}


/* ========================================================= */
/* HMAC-SHA256                                               */
/* ========================================================= */

static void hmac_sha256(
    const u8 *key,
    size_t key_size,
    const u8 *data,
    size_t data_size,
    u8 output[HASH_SIZE]
)
{
    u8 key_block[64];
    u8 inner_pad[64];
    u8 outer_pad[64];
    u8 inner_hash[HASH_SIZE];

    memset(
        key_block,
        0,
        sizeof(key_block)
    );

    if (
        key_size >
        sizeof(key_block)
    ) {
        sha256CalculateHash(
            key_block,
            key,
            key_size
        );
    }
    else {
        memcpy(
            key_block,
            key,
            key_size
        );
    }

    for (
        size_t i = 0;
        i < 64;
        i++
    ) {
        inner_pad[i] =
            key_block[i] ^ 0x36;

        outer_pad[i] =
            key_block[i] ^ 0x5c;
    }

    Sha256Context ctx;

    sha256ContextCreate(
        &ctx
    );

    sha256ContextUpdate(
        &ctx,
        inner_pad,
        sizeof(inner_pad)
    );

    sha256ContextUpdate(
        &ctx,
        data,
        data_size
    );

    sha256ContextGetHash(
        &ctx,
        inner_hash
    );

    sha256ContextCreate(
        &ctx
    );

    sha256ContextUpdate(
        &ctx,
        outer_pad,
        sizeof(outer_pad)
    );

    sha256ContextUpdate(
        &ctx,
        inner_hash,
        sizeof(inner_hash)
    );

    sha256ContextGetHash(
        &ctx,
        output
    );

    secure_zero(
        key_block,
        sizeof(key_block)
    );

    secure_zero(
        inner_pad,
        sizeof(inner_pad)
    );

    secure_zero(
        outer_pad,
        sizeof(outer_pad)
    );

    secure_zero(
        inner_hash,
        sizeof(inner_hash)
    );
}


/* ========================================================= */
/* PBKDF2-HMAC-SHA256                                        */
/* ========================================================= */

static void derive_password_hash(
    const char *password,
    const u8 salt[SALT_SIZE],
    u32 iterations,
    u8 output[HASH_SIZE]
)
{
    u8 input[
        SALT_SIZE + 4
    ];

    memcpy(
        input,
        salt,
        SALT_SIZE
    );

    /*
     * PBKDF2 block number 1,
     * big endian.
     */
    input[SALT_SIZE + 0] = 0;
    input[SALT_SIZE + 1] = 0;
    input[SALT_SIZE + 2] = 0;
    input[SALT_SIZE + 3] = 1;

    u8 u[HASH_SIZE];
    u8 t[HASH_SIZE];

    hmac_sha256(
        (const u8 *)password,
        strlen(password),
        input,
        sizeof(input),
        u
    );

    memcpy(
        t,
        u,
        sizeof(t)
    );

    for (
        u32 i = 1;
        i < iterations;
        i++
    ) {
        u8 next[HASH_SIZE];

        hmac_sha256(
            (const u8 *)password,
            strlen(password),
            u,
            sizeof(u),
            next
        );

        memcpy(
            u,
            next,
            sizeof(u)
        );

        for (
            size_t x = 0;
            x < HASH_SIZE;
            x++
        ) {
            t[x] ^= u[x];
        }

        secure_zero(
            next,
            sizeof(next)
        );
    }

    memcpy(
        output,
        t,
        HASH_SIZE
    );

    secure_zero(
        input,
        sizeof(input)
    );

    secure_zero(
        u,
        sizeof(u)
    );

    secure_zero(
        t,
        sizeof(t)
    );
}


/* ========================================================= */
/* Password file                                             */
/* ========================================================= */

static void ensure_directory(void)
{
    mkdir(
        "sdmc:/config",
        0777
    );

    mkdir(
        AUTH_DIR,
        0777
    );
}


static bool load_auth_file(void)
{
    FILE *f =
        fopen(
            AUTH_FILE,
            "rb"
        );

    if (!f)
        return false;

    char magic[
        AUTH_MAGIC_SIZE
    ];

    u32 version = 0;
    u32 iterations = 0;

    bool ok =
        fread(
            magic,
            1,
            sizeof(magic),
            f
        ) == sizeof(magic) &&

        fread(
            &version,
            1,
            sizeof(version),
            f
        ) == sizeof(version) &&

        fread(
            &iterations,
            1,
            sizeof(iterations),
            f
        ) == sizeof(iterations) &&

        fread(
            g_salt,
            1,
            sizeof(g_salt),
            f
        ) == sizeof(g_salt) &&

        fread(
            g_hash,
            1,
            sizeof(g_hash),
            f
        ) == sizeof(g_hash);

    fclose(f);

    if (!ok)
        return false;

    if (
        memcmp(
            magic,
            AUTH_MAGIC,
            AUTH_MAGIC_SIZE
        ) != 0
    ) {
        return false;
    }

    if (
        version !=
        AUTH_VERSION
    ) {
        return false;
    }

    if (
        iterations <
        10000
    ) {
        return false;
    }

    g_iterations =
        iterations;

    g_loaded = true;

    return true;
}


static bool save_auth_file(void)
{
    ensure_directory();

    FILE *f =
        fopen(
            AUTH_FILE,
            "wb"
        );

    if (!f)
        return false;

    u32 version =
        AUTH_VERSION;

    bool ok =
        fwrite(
            AUTH_MAGIC,
            1,
            AUTH_MAGIC_SIZE,
            f
        ) == AUTH_MAGIC_SIZE &&

        fwrite(
            &version,
            1,
            sizeof(version),
            f
        ) == sizeof(version) &&

        fwrite(
            &g_iterations,
            1,
            sizeof(g_iterations),
            f
        ) == sizeof(g_iterations) &&

        fwrite(
            g_salt,
            1,
            sizeof(g_salt),
            f
        ) == sizeof(g_salt) &&

        fwrite(
            g_hash,
            1,
            sizeof(g_hash),
            f
        ) == sizeof(g_hash);

    fclose(f);

    return ok;
}


/* ========================================================= */
/* Switch keyboard                                           */
/* ========================================================= */

static bool ask_password(
    const char *title,
    char *output,
    size_t output_size
)
{
    SwkbdConfig keyboard;

    Result rc =
        swkbdCreate(
            &keyboard,
            0
        );

    if (R_FAILED(rc))
        return false;

    swkbdConfigMakePresetPassword(
        &keyboard
    );

    swkbdConfigSetHeaderText(
        &keyboard,
        title
    );

    output[0] = '\0';

    rc =
        swkbdShow(
            &keyboard,
            output,
            output_size
        );

    swkbdClose(
        &keyboard
    );

    return
        R_SUCCEEDED(rc) &&
        output[0] != '\0';
}


static bool create_password(void)
{
    char password[256];
    char confirm[256];

    for (;;) {
        memset(
            password,
            0,
            sizeof(password)
        );

        memset(
            confirm,
            0,
            sizeof(confirm)
        );

        if (
            !ask_password(
                "Set remote access password",
                password,
                sizeof(password)
            )
        ) {
            return false;
        }

        if (
            strlen(password) < 8
        ) {
            printf(
                "Password must be at least "
                "8 characters.\n"
            );

            consoleUpdate(NULL);
            continue;
        }

        if (
            !ask_password(
                "Confirm remote access password",
                confirm,
                sizeof(confirm)
            )
        ) {
            secure_zero(
                password,
                sizeof(password)
            );

            return false;
        }

        if (
            strcmp(
                password,
                confirm
            ) != 0
        ) {
            printf(
                "Passwords did not match. "
                "Try again.\n"
            );

            consoleUpdate(NULL);

            secure_zero(
                password,
                sizeof(password)
            );

            secure_zero(
                confirm,
                sizeof(confirm)
            );

            continue;
        }

        if (
            !secure_random(
                g_salt,
                sizeof(g_salt)
            )
        ) {
            secure_zero(
                password,
                sizeof(password)
            );

            secure_zero(
                confirm,
                sizeof(confirm)
            );

            return false;
        }

        g_iterations =
            AUTH_ITERATIONS;

        derive_password_hash(
            password,
            g_salt,
            g_iterations,
            g_hash
        );

        secure_zero(
            password,
            sizeof(password)
        );

        secure_zero(
            confirm,
            sizeof(confirm)
        );

        if (
            !save_auth_file()
        ) {
            return false;
        }

        g_loaded = true;

        return true;
    }
}


/* ========================================================= */
/* Public password API                                       */
/* ========================================================= */

bool remote_auth_ensure_password(void)
{
    ensure_directory();

    if (
        load_auth_file()
    ) {
        return true;
    }

    printf(
        "No remote password configured.\n"
        "Opening Switch keyboard...\n"
    );

    consoleUpdate(NULL);

    return create_password();
}


bool remote_auth_verify(
    const char *password
)
{
    if (
        !g_loaded ||
        !password
    ) {
        return false;
    }

    u8 candidate[HASH_SIZE];

    derive_password_hash(
        password,
        g_salt,
        g_iterations,
        candidate
    );

    bool ok =
        constant_equal(
            candidate,
            g_hash,
            sizeof(candidate)
        );

    secure_zero(
        candidate,
        sizeof(candidate)
    );

    return ok;
}


/* ========================================================= */
/* Sessions                                                  */
/* ========================================================= */

static void bytes_to_hex(
    const u8 *bytes,
    size_t byte_count,
    char *output
)
{
    static const char hex[] =
        "0123456789abcdef";

    for (
        size_t i = 0;
        i < byte_count;
        i++
    ) {
        output[
            i * 2
        ] =
            hex[
                bytes[i] >> 4
            ];

        output[
            i * 2 + 1
        ] =
            hex[
                bytes[i] & 0x0f
            ];
    }

    output[
        byte_count * 2
    ] = '\0';
}


bool remote_auth_create_session(
    const char *client_ip,
    char *token_out,
    size_t token_out_size
)
{
    if (
        !client_ip ||
        !token_out ||
        token_out_size <
            SESSION_TOKEN_SIZE
    ) {
        return false;
    }

    u8 random_bytes[
        SESSION_RANDOM_SIZE
    ];

    if (
        !secure_random(
            random_bytes,
            sizeof(random_bytes)
        )
    ) {
        return false;
    }

    char token[
        SESSION_TOKEN_SIZE
    ];

    bytes_to_hex(
        random_bytes,
        sizeof(random_bytes),
        token
    );

    secure_zero(
        random_bytes,
        sizeof(random_bytes)
    );

    unsigned slot =
        g_next_session %
        MAX_SESSIONS;

    g_next_session++;

    memset(
        &g_sessions[slot],
        0,
        sizeof(g_sessions[slot])
    );

    g_sessions[slot].used =
        true;

    snprintf(
        g_sessions[slot].token,
        sizeof(g_sessions[slot].token),
        "%s",
        token
    );

    snprintf(
        g_sessions[slot].ip,
        sizeof(g_sessions[slot].ip),
        "%s",
        client_ip
    );

    snprintf(
        token_out,
        token_out_size,
        "%s",
        token
    );

    secure_zero(
        token,
        sizeof(token)
    );

    return true;
}


bool remote_auth_session_valid(
    const char *token,
    const char *client_ip
)
{
    if (
        !token ||
        !client_ip
    ) {
        return false;
    }

    for (
        int i = 0;
        i < MAX_SESSIONS;
        i++
    ) {
        if (
            !g_sessions[i].used
        ) {
            continue;
        }

        if (
            strcmp(
                g_sessions[i].ip,
                client_ip
            ) != 0
        ) {
            continue;
        }

        if (
            strlen(token) !=
            strlen(
                g_sessions[i].token
            )
        ) {
            continue;
        }

        if (
            constant_equal(
                (const u8 *)token,
                (const u8 *)
                    g_sessions[i].token,
                strlen(token)
            )
        ) {
            return true;
        }
    }

    return false;
}


void remote_auth_revoke_session(
    const char *token,
    const char *client_ip
)
{
    if (
        !token ||
        !client_ip
    ) {
        return;
    }

    for (
        int i = 0;
        i < MAX_SESSIONS;
        i++
    ) {
        if (
            g_sessions[i].used &&
            strcmp(
                g_sessions[i].token,
                token
            ) == 0 &&
            strcmp(
                g_sessions[i].ip,
                client_ip
            ) == 0
        ) {
            secure_zero(
                &g_sessions[i],
                sizeof(g_sessions[i])
            );
        }
    }
}


void remote_auth_revoke_all(void)
{
    secure_zero(
        g_sessions,
        sizeof(g_sessions)
    );
}
