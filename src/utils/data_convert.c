#include "utils/data_convert.h"

#include <stdint.h>
#include <string.h>

char *toupper_str(char *input_str, char *output_str)
{
    int len_str = strlen(input_str);

    for (int i = 0; i <= len_str; i++)
    {
        output_str[i] = toupper(input_str[i]);
    }

    return (output_str);
}

void octet_hex_to_bit(char *hex, char *bit)
{
    char tmp_hex[3];

    tmp_hex[0] = hex[0];
    tmp_hex[1] = hex[1];
    tmp_hex[2] = 0;

    int n = strtol(tmp_hex, NULL, 16);

    bit[0] = 0x01 & (n >> 0);
    bit[1] = 0x01 & (n >> 1);
    bit[2] = 0x01 & (n >> 2);
    bit[3] = 0x01 & (n >> 3);
    bit[4] = 0x01 & (n >> 4);
    bit[5] = 0x01 & (n >> 5);
    bit[6] = 0x01 & (n >> 6);
    bit[7] = 0x01 & (n >> 7);
}

void int_to_bit(int n, uint8_t *bit)
{
    bit[0] = 0x01 & (n >> 0);
    bit[1] = 0x01 & (n >> 1);
    bit[2] = 0x01 & (n >> 2);
    bit[3] = 0x01 & (n >> 3);
    bit[4] = 0x01 & (n >> 4);
    bit[5] = 0x01 & (n >> 5);
    bit[6] = 0x01 & (n >> 6);
    bit[7] = 0x01 & (n >> 7);
}

void uint32_to_bit_array(uint32_t uint32_in, uint8_t *bit)
{
    int i;
    uint32_t uint32_tmp = uint32_in;
    for (i = 0; i < 32; i++)
    {
        bit[i] = 0x01 & uint32_tmp;
        uint32_tmp = (uint32_tmp >> 1);
    }
}

void byte_array_to_bit_array(uint8_t *byte_in, int num_byte, uint8_t *bit)
{
    int j = 0;
    for (int i = 0; i < num_byte * 8; i = i + 8)
    {
        int_to_bit(byte_in[j], bit + i);
        j++;
    }
}

int convert_hex_to_bit(char *hex, char *bit)
{
    int num_hex = strlen(hex);
    while (hex[num_hex - 1] <= 32 || hex[num_hex - 1] >= 127)
    {
        num_hex--;
    }

    if (num_hex % 2 != 0)
    {
        printf("convert_hex_to_bit: Half octet is encountered! num_hex %d\n", num_hex);
        printf("%s\n", hex);
        return (-1);
    }

    int num_bit = num_hex * 4;

    int j = 0;
    for (int i = 0; i < num_hex; i = i + 2)
    {
        j = i * 4;
        octet_hex_to_bit(hex + i, bit + j);
    }

    return (num_bit);
}