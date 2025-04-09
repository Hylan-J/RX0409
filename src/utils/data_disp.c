#include "utils/data_disp.h"

#include <stdint.h>
#include <stdio.h>

void disp_bit(char *bit, int num_bit)
{
    int i, bit_val;
    for (i = 0; i < num_bit; i++)
    {
        bit_val = bit[i];
        if (i % 8 == 0 && i != 0)
        {
            printf(" ");
        }
        else if (i % 4 == 0 && i != 0)
        {
            printf("-");
        }
        printf("%d", bit_val);
    }
    printf("\n");
}

void disp_bit_in_hex(char *bit, int num_bit)
{
    int i, a;
    for (i = 0; i < num_bit; i = i + 8)
    {
        a = bit[i] + bit[i + 1] * 2 + bit[i + 2] * 4 + bit[i + 3] * 8 + bit[i + 4] * 16 + bit[i + 5] * 32 +
            bit[i + 6] * 64 + bit[i + 7] * 128;
        // a = bit[i+7] + bit[i+6]*2 + bit[i+5]*4 + bit[i+4]*8 + bit[i+3]*16 + bit[i+2]*32 + bit[i+1]*64 + bit[i]*128;
        printf("%02x", a);
    }
    printf("\n");
}

void disp_hex(uint8_t *hex, int num_hex)
{
    int i;
    for (i = 0; i < num_hex; i++)
    {
        printf("%02x", hex[i]);
    }
    printf("\n");
}

void disp_hex_in_bit(uint8_t *hex, int num_hex)
{
    int i, j, bit_val;

    for (j = 0; j < num_hex; j++)
    {

        for (i = 0; i < 8; i++)
        {
            bit_val = (hex[j] >> i) & 0x01;
            if (i == 4)
            {
                printf("-");
            }
            printf("%d", bit_val);
        }

        printf(" ");
    }

    printf("\n");
}
