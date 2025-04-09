#include "boards/hackrf_oper.h"

#include <hackrf.h>
#include <stdio.h>
#include <stdint.h>

#ifdef _MSC_VER
#include <windows.h>
#else
#include <signal.h>
#endif

volatile bool exit_status = false;

#ifdef _MSC_VER
BOOL WINAPI sighandler_for_windows(int signum)
{
    if (CTRL_C_EVENT == signum)
    {
        fprintf(stdout, "Caught signal %d\n", signum);
        exit_status = true;
        return TRUE;
    }
    return FALSE;
}
#else
void sighandler_for_others(int signum)
{
    fprintf(stdout, "Caught signal %d\n", signum);
    exit_status = true;
}
#endif

int rx_callback(hackrf_transfer *transfer)
{
    hackrf_rx_context *ctx = (hackrf_rx_context *)transfer->rx_ctx; // 获取上下文
    int8_t *p = (int8_t *)transfer->buffer;

    for (int i = 0; i < transfer->valid_length; i++)
    {
        ctx->rx_buf[ctx->rx_buf_offset] = p[i];
        ctx->rx_buf_offset = (ctx->rx_buf_offset + 1) & (ctx->len_buf - 1); // 循环缓冲区
    }

    return 0;
}

int init_board()
{
    int result = hackrf_init();
    if (result != HACKRF_SUCCESS)
    {
        printf("open_board: hackrf_init() failed: %s (%d)\n", hackrf_error_name(result), result);
        return (-1);
    }

#ifdef _MSC_VER
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)sighandler_for_windows, TRUE);
#else
    signal(SIGINT, &sighandler_for_others);
    signal(SIGILL, &sighandler_for_others);
    signal(SIGFPE, &sighandler_for_others);
    signal(SIGSEGV, &sighandler_for_others);
    signal(SIGTERM, &sighandler_for_others);
    signal(SIGABRT, &sighandler_for_others);
#endif

    return (0);
}

int board_set_freq(void *device, uint64_t freq_hz)
{
    int result = hackrf_set_freq((hackrf_device *)device, freq_hz);
    if (result != HACKRF_SUCCESS)
    {
        printf("board_set_freq: hackrf_set_freq() failed: %s (%d)\n", hackrf_error_name(result), result);
        return (-1);
    }
    return (HACKRF_SUCCESS);
}

inline int open_board(uint64_t freq_hz, int gain, int lnaGain, uint8_t amp, hackrf_device **device)
{
    int result;

    result = hackrf_open(device);
    if (result != HACKRF_SUCCESS)
    {
        printf("open_board: hackrf_open() failed: %s (%d)\n", hackrf_error_name(result), result);
        return (-1);
    }

    result = hackrf_set_freq(*device, freq_hz);
    if (result != HACKRF_SUCCESS)
    {
        printf("open_board: hackrf_set_freq() failed: %s (%d)\n", hackrf_error_name(result), result);
        return (-1);
    }

    result = hackrf_set_sample_rate(*device, SAMPLE_PER_SYMBOL * 1000000ul);
    if (result != HACKRF_SUCCESS)
    {
        printf("open_board: hackrf_set_sample_rate() failed: %s (%d)\n", hackrf_error_name(result), result);
        return (-1);
    }

    result = hackrf_set_baseband_filter_bandwidth(*device, SAMPLE_PER_SYMBOL * 1000000ul / 2);
    if (result != HACKRF_SUCCESS)
    {
        printf("open_board: hackrf_set_baseband_filter_bandwidth() failed: %s (%d)\n", hackrf_error_name(result),
               result);
        return (-1);
    }

    printf("Setting VGA gain to %d\n", gain);
    result = hackrf_set_vga_gain(*device, gain);
    if (result != HACKRF_SUCCESS)
    {
        printf("open_board: hackrf_set_vga_gain() failed: %s (%d)\n", hackrf_error_name(result), result);
        return (-1);
    }

    printf("Setting LNA gain to %d\n", lnaGain);
    result = hackrf_set_lna_gain(*device, lnaGain);
    if (result != HACKRF_SUCCESS)
    {
        printf("open_board: hackrf_set_lna_gain() failed: %s (%d)\n", hackrf_error_name(result), result);
        return (-1);
    }

    printf(amp ? "Enabling amp\n" : "Disabling amp\n");
    result = hackrf_set_amp_enable(*device, amp);
    if (result != HACKRF_SUCCESS)
    {
        printf("open_board: hackrf_set_amp_enable() failed: %s (%d)\n", hackrf_error_name(result), result);
        return (-1);
    }

    return (0);
}

void exit_board(hackrf_device *device)
{
    if (device != NULL)
    {
        hackrf_exit();
        printf("hackrf_exit() done\n");
    }
}

inline int close_board(hackrf_device *device)
{
    int result;

    if (device != NULL)
    {
        result = hackrf_stop_rx(device);
        if (result != HACKRF_SUCCESS)
        {
            printf("close_board: hackrf_stop_rx() failed: %s (%d)\n", hackrf_error_name(result), result);
            return (-1);
        }

        result = hackrf_close(device);
        if (result != HACKRF_SUCCESS)
        {
            printf("close_board: hackrf_close() failed: %s (%d)\n", hackrf_error_name(result), result);
            return (-1);
        }

        return (0);
    }
    else
    {
        return (-1);
    }
}

inline int run_board(hackrf_device *device, hackrf_rx_context *ctx)
{
    int result;

    result = hackrf_start_rx(device, rx_callback, ctx);
    if (result != HACKRF_SUCCESS)
    {
        printf("run_board: hackrf_start_rx() failed: %s (%d)\n", hackrf_error_name(result), result);
        return (-1);
    }
    return (0);
}

inline int config_run_board(uint64_t freq_hz, int gain, int lnaGain, uint8_t amp, void **rf_dev, hackrf_rx_context *ctx)
{
    hackrf_device *dev = NULL;

    (*rf_dev) = dev;

    if (init_board() != 0)
    {
        return (-1);
    }

    if (open_board(freq_hz, gain, lnaGain, amp, &dev) != 0)
    {
        (*rf_dev) = dev;
        return (-1);
    }

    (*rf_dev) = dev;
    if (run_board(dev, ctx) != 0)
    {
        return (-1);
    }

    return (0);
}

void stop_close_board(hackrf_device *device)
{
    if (close_board(device) != 0)
    {
        return;
    }
    exit_board(device);
}