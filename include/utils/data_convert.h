#ifndef DATA_CONVERT_H
#define DATA_CONVERT_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

char *toupper_str(char *input_str, char *output_str);

void octet_hex_to_bit(char *hex, char *bit);

void int_to_bit(int n, uint8_t *bit);

void uint32_to_bit_array(uint32_t uint32_in, uint8_t *bit);

void byte_array_to_bit_array(uint8_t *byte_in, int num_byte, uint8_t *bit);

int convert_hex_to_bit(char *hex, char *bit);

#endif // DATA_CONVERT_H