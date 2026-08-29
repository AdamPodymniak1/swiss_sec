#include "randombytes.h"
#include <esp_system.h>
#include <stdint.h>
#include <stddef.h>

int PQCLEAN_randombytes(uint8_t *buf, size_t n) {
    esp_fill_random(buf, n);
    return 0;
}