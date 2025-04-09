#include "ble/channel.h"

#include <stdbool.h>
#include <stdint.h>

uint64_t get_freq_by_channel_number(int channel_number)
{
    uint64_t freq_hz;
    if (channel_number == 37)
    {
        freq_hz = 2402000000ull;
    }
    else if (channel_number == 38)
    {
        freq_hz = 2426000000ull;
    }
    else if (channel_number == 39)
    {
        freq_hz = 2480000000ull;
    }
    else if (channel_number >= 0 && channel_number <= 10)
    {
        freq_hz = 2404000000ull + channel_number * 2000000ull;
    }
    else if (channel_number >= 11 && channel_number <= 36)
    {
        freq_hz = 2428000000ull + (channel_number - 11) * 2000000ull;
    }
    else
    {
        freq_hz = 0xffffffffffffffff;
    }
    return (freq_hz);
}

bool chm_is_full_map(uint8_t *chm)
{
    if ((chm[0] == 0x1F) && (chm[1] == 0xFF) && (chm[2] == 0xFF) && (chm[3] == 0xFF) && (chm[4] == 0xFF))
    {
        return (true);
    }
    return (false);
}