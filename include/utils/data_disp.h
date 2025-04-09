#ifndef DATA_DISP_H
#define DATA_DISP_H

#include <stdint.h>
#include <stdio.h>

void disp_bit(char *bit, int num_bit);
void disp_bit_in_hex(char *bit, int num_bit);
void disp_hex(uint8_t *hex, int num_hex);
void disp_hex_in_bit(uint8_t *hex, int num_hex);

#endif // DATA_DISP_H