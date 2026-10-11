#pragma once

#include <stdbool.h>
#include <stddef.h>

bool alldebrid_pin_start(
    char *error,
    size_t error_size
);

bool alldebrid_pin_check(
    bool *activated,
    char *apikey,
    size_t apikey_size,
    char *error,
    size_t error_size
);

bool alldebrid_pin_pending(void);

const char *alldebrid_pin_code(void);

int alldebrid_pin_expires(void);

void alldebrid_pin_reset(void);
