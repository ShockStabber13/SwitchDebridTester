#include "archive_extract.h"

#include <archive.h>
#include <archive_entry.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define EXTRACT_BUFFER_SIZE (1024 * 1024)

static bool is_archive(const char *path)
{
    size_t n = strlen(path);

    return
        (n >= 4 && strcasecmp(path+n-4, ".zip") == 0) ||
        (n >= 4 && strcasecmp(path+n-4, ".rar") == 0) ||
        (n >= 3 && strcasecmp(path+n-3, ".7z") == 0);
}

static bool destination_path(
    const char *archive,
    char *out,
    size_t size
)
{
    size_t n = strlen(archive);
    size_t cut = 0;

    if (
        n >= 4 &&
        (
            strcasecmp(archive+n-4, ".zip") == 0 ||
            strcasecmp(archive+n-4, ".rar") == 0
        )
    )
        cut = 4;
    else if (
        n >= 3 &&
        strcasecmp(archive+n-3, ".7z") == 0
    )
        cut = 3;
    else
        return false;

    if (n <= cut || n-cut+1 > size)
        return false;

    memcpy(out, archive, n-cut);
    out[n-cut] = 0;

    return true;
}

static bool mkdir_recursive(const char *path)
{
    char tmp[4096];

    if (strlen(path) >= sizeof(tmp))
        return false;

    snprintf(tmp, sizeof(tmp), "%s", path);

    char *start = tmp;
    char *colon = strchr(tmp, ':');

    if (colon && colon[1] == '/')
        start = colon + 2;

    for (char *p = start; *p; p++) {
        if (*p != '/')
            continue;

        *p = 0;

        if (
            tmp[0] &&
            mkdir(tmp, 0777) != 0 &&
            errno != EEXIST
        ) {
            *p = '/';
            return false;
        }

        *p = '/';
    }

    return
        mkdir(tmp, 0777) == 0 ||
        errno == EEXIST;
}

static bool mkdir_parent(const char *path)
{
    char tmp[4096];

    if (strlen(path) >= sizeof(tmp))
        return false;

    snprintf(tmp, sizeof(tmp), "%s", path);

    char *slash = strrchr(tmp, '/');

    if (!slash)
        return true;

    *slash = 0;

    return mkdir_recursive(tmp);
}

static bool safe_path(
    const char *input,
    char *output,
    size_t size
)
{
    char tmp[4096];

    if (!input || strlen(input) >= sizeof(tmp))
        return false;

    snprintf(tmp, sizeof(tmp), "%s", input);

    for (char *p = tmp; *p; p++)
        if (*p == '\\')
            *p = '/';

    if (tmp[0] == '/' || strchr(tmp, ':'))
        return false;

    output[0] = 0;
    size_t used = 0;

    char *save = NULL;

    for (
        char *part = strtok_r(tmp, "/", &save);
        part;
        part = strtok_r(NULL, "/", &save)
    ) {
        if (strcmp(part, "..") == 0)
            return false;

        if (
            strcmp(part, ".") == 0 ||
            !part[0]
        )
            continue;

        size_t len = strlen(part);
        size_t need = len + (used ? 1 : 0);

        if (used + need + 1 > size)
            return false;

        if (used)
            output[used++] = '/';

        memcpy(output + used, part, len);

        used += len;
        output[used] = 0;
    }

    return used > 0;
}

static void remove_tree(const char *path)
{
    DIR *dir = opendir(path);

    if (!dir) {
        remove(path);
        return;
    }

    struct dirent *entry;

    while ((entry = readdir(dir))) {
        if (
            strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0
        )
            continue;

        char child[4096];

        if (
            snprintf(
                child,
                sizeof(child),
                "%s/%s",
                path,
                entry->d_name
            ) >= (int)sizeof(child)
        )
            continue;

        struct stat st;

        if (
            stat(child, &st) == 0 &&
            S_ISDIR(st.st_mode)
        )
            remove_tree(child);
        else
            remove(child);
    }

    closedir(dir);
    rmdir(path);
}

bool archive_extract_if_needed(
    const char *archive_path,
    char *error,
    size_t error_size
)
{
    if (!is_archive(archive_path))
        return true;

    char dest[4096];

    if (!destination_path(
            archive_path,
            dest,
            sizeof(dest)
        )) {
        snprintf(
            error,
            error_size,
            "Invalid extraction path"
        );
        return false;
    }

    struct stat st;

    if (stat(dest, &st) == 0) {
        snprintf(
            error,
            error_size,
            "Extraction folder already exists"
        );
        return false;
    }

    if (!mkdir_recursive(dest)) {
        snprintf(
            error,
            error_size,
            "Could not create extraction folder"
        );
        return false;
    }

    struct archive *a =
        archive_read_new();

    if (!a) {
        remove_tree(dest);
        return false;
    }

    archive_read_support_filter_all(a);
    archive_read_support_format_zip(a);
    archive_read_support_format_7zip(a);
    archive_read_support_format_rar(a);
    archive_read_support_format_rar5(a);

    if (
        archive_read_open_filename(
            a,
            archive_path,
            EXTRACT_BUFFER_SIZE
        ) != ARCHIVE_OK
    ) {
        snprintf(
            error,
            error_size,
            "%s",
            archive_error_string(a)
                ? archive_error_string(a)
                : "Could not open archive"
        );

        archive_read_free(a);
        remove_tree(dest);
        return false;
    }

    unsigned char *buffer =
        malloc(EXTRACT_BUFFER_SIZE);

    if (!buffer) {
        archive_read_free(a);
        remove_tree(dest);
        return false;
    }

    bool ok = true;
    struct archive_entry *entry;

    while (ok) {
        int rc =
            archive_read_next_header(
                a,
                &entry
            );

        if (rc == ARCHIVE_EOF)
            break;

        if (rc != ARCHIVE_OK) {
            snprintf(
                error,
                error_size,
                "%s",
                archive_error_string(a)
            );

            ok = false;
            break;
        }

        char relative[4096];

        if (
            !safe_path(
                archive_entry_pathname(entry),
                relative,
                sizeof(relative)
            )
        ) {
            snprintf(
                error,
                error_size,
                "Unsafe archive path"
            );

            ok = false;
            break;
        }

        if (
            archive_entry_symlink(entry) ||
            archive_entry_hardlink(entry)
        ) {
            snprintf(
                error,
                error_size,
                "Archive links are not supported"
            );

            ok = false;
            break;
        }

        char target[4096];

        if (
            snprintf(
                target,
                sizeof(target),
                "%s/%s",
                dest,
                relative
            ) >= (int)sizeof(target)
        ) {
            ok = false;
            break;
        }

        mode_t type =
            archive_entry_filetype(entry);

        if (type == AE_IFDIR) {
            ok = mkdir_recursive(target);
            continue;
        }

        if (
            type != AE_IFREG &&
            type != 0
        ) {
            ok = false;
            break;
        }

        if (!mkdir_parent(target)) {
            ok = false;
            break;
        }

        FILE *out =
            fopen(target, "wb");

        if (!out) {
            ok = false;
            break;
        }

        for (;;) {
            la_ssize_t got =
                archive_read_data(
                    a,
                    buffer,
                    EXTRACT_BUFFER_SIZE
                );

            if (got == 0)
                break;

            if (got < 0) {
                ok = false;
                break;
            }

            if (
                fwrite(
                    buffer,
                    1,
                    got,
                    out
                ) != (size_t)got
            ) {
                ok = false;
                break;
            }
        }

        fclose(out);
    }

    free(buffer);

    archive_read_close(a);
    archive_read_free(a);

    if (!ok) {
        remove_tree(dest);

        if (!error[0])
            snprintf(
                error,
                error_size,
                "Extraction failed"
            );

        return false;
    }

    if (remove(archive_path) != 0) {
        snprintf(
            error,
            error_size,
            "Extracted but could not delete archive"
        );

        return false;
    }

    return true;
}
