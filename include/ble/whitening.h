#ifndef WHITENING_H
#define WHITENING_H

#include <stdint.h>

extern const uint8_t whitening_tables[40][42];
void dewhitening_bytes(uint8_t *byte_in, int num_byte, const uint8_t *scramble_table_byte, uint8_t *byte_out);

#endif // WHITENING_H