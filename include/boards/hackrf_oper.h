#ifndef HACKRF_OPER_H
#define HACKRF_OPER_H

#define MAX_GAIN 62
#define DEFAULT_GAIN 6

#include <hackrf.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _MSC_VER
#include <windows.h>
#else
#include <signal.h>
#endif

typedef struct
{
    int8_t *rx_buf;         // 接收缓冲区
    uint32_t rx_buf_offset; // 缓冲区偏移量
    uint32_t len_buf;       // 缓冲区长度
} hackrf_rx_context;

extern volatile bool exit_status;

#ifdef _MSC_VER
BOOL WINAPI sighandler_for_windows(int signum);
#else
void sighandler_for_others(int signum);
#endif

int rx_callback(hackrf_transfer *transfer);
int init_board();
int board_set_freq(void *device, uint64_t freq_hz);
inline int open_board(uint64_t freq_hz, int gain, int lnaGain, uint8_t amp, hackrf_device **device);
inline int config_run_board(uint64_t freq_hz, int gain, int lnaGain, uint8_t amp, void **rf_dev, hackrf_rx_context *ctx);
inline int run_board(hackrf_device *device, hackrf_rx_context *ctx);
inline int close_board(hackrf_device *device);
void stop_close_board(hackrf_device *device);
void exit_board(hackrf_device *device);

void set_exit_status(bool status);
bool get_exit_status();

#endif // HACKRF_OPER_H