#ifndef ARCHIVE_EXTRACT_H
#define ARCHIVE_EXTRACT_H

#include <stdbool.h>
#include <stddef.h>

bool archive_extract_if_needed(
    const char *archive_path,
    char *error,
    size_t error_size
);

#endif
