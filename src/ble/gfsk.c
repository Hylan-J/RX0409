#include "ble/gfsk.h"

#include <stdint.h>

void demodulate_byte(int8_t *rxp, int num_byte, uint8_t *out_byte, int sps)
{
    int i, j;
    int I0, Q0, I1, Q1;
    uint8_t bit_decision;
    int sample_idx = 0;

    for (i = 0; i < num_byte; i++)
    {
        out_byte[i] = 0;
        for (j = 0; j < 8; j++)
        {
            I0 = rxp[sample_idx];
            Q0 = rxp[sample_idx + 1];
            I1 = rxp[sample_idx + 2];
            Q1 = rxp[sample_idx + 3];
            bit_decision = (I0 * Q1 - I1 * Q0) > 0 ? 1 : 0;
            out_byte[i] = out_byte[i] | (bit_decision << j);

            sample_idx = sample_idx + sps * 2;
        }
    }
}