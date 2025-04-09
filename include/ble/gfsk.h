#ifndef GFSK_H
#define GFSK_H

#include <stdint.h>

void demodulate_byte(int8_t *rxp, int num_byte, uint8_t *out_byte, int sps);

#endif