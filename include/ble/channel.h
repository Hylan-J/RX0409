#ifndef CHANNEL_H
#define CHANNEL_H

#include <stdint.h>
#include <stdbool.h>

uint64_t get_freq_by_channel_number(int channel_number);

bool chm_is_full_map(uint8_t *chm);

#endif // CHANNEL_H