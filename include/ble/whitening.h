#ifndef WHITENING_H
#define WHITENING_H

#include <stdint.h>

extern const uint8_t whitening_tables[40][42];
void dewhitening_bytes(uint8_t *in_bytes, int num_bytes, const uint8_t *dewhitening_table_byte, uint8_t *out_bytes);

#endif // WHITENING_H