#ifndef CRC_H
#define CRC_H

#include <stdbool.h>
#include <stdint.h>

extern const uint_fast32_t crc_table[256];

uint_fast32_t crc_update(uint_fast32_t crc, const void *data, size_t data_len);
uint_fast32_t crc24_byte(uint8_t *byte_in, int num_byte, uint32_t init_hex);
uint32_t crc_init_reorder(uint32_t crc_init);
bool crc_check(uint8_t *tmp_byte, int body_len, uint32_t crc_init);

#endif