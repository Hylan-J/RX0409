// Bluetooth Low Energy SDR sniffer by Xianjun Jiao (putaoshu@msn.com)

#include "common.h"
#include <pthread.h>

#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/in.h>

#include "ble/channel.h"
#include "ble/crc.h"
#include "ble/gfsk.h"
#include "ble/whitening.h"

#include "utils/data_convert.h"
#include "utils/data_disp.h"
#include "utils/data_rw.h"

#include "boards/hackrf_oper.h"

#ifdef _WIN32
#include <windows.h>

#ifdef _MSC_VER

#ifdef _WIN64
typedef int64_t ssize_t;
#else
typedef int32_t ssize_t;
#endif

#define strtoull _strtoui64
#define snprintf _snprintf

int gettimeofday(struct timeval *tv, void *ignored)
{
    FILETIME ft;
    unsigned __int64 tmp = 0;
    if (NULL != tv)
    {
        GetSystemTimeAsFileTime(&ft);
        tmp |= ft.dwHighDateTime;
        tmp <<= 32;
        tmp |= ft.dwLowDateTime;
        tmp /= 10;
        tmp -= 11644473600000000Ui64;
        tv->tv_sec = (long)(tmp / 1000000UL);
        tv->tv_usec = (long)(tmp % 1000000UL);
    }
    return 0;
}

#endif
#endif

#if defined(__GNUC__)
#include <sys/time.h>
#include <unistd.h>
#endif

char *board_name = "HACKRF";

#include <signal.h>

#if defined _WIN32
#define sleep(a) Sleep((a * 1000))
#endif

static inline int TimevalDiff(const struct timeval *a, const struct timeval *b)
{
    return ((a->tv_sec - b->tv_sec) * 1000000 + (a->tv_usec - b->tv_usec));
}

/* File handling for pcap + BTLE, don't use btbb as it's too buggy and slow */
// TCPDUMP_MAGIC PCAP_VERSION_MAJOR PCAP_VERSION_MINOR thiszone sigfigs snaplen linktype (DLT_BLUETOOTH_LE_LL_WITH_PHDR)
// 0xa1b2c3d4 \x00\x02 \x00\x04 \x00\x00\x00\x00 \x00\x00\x00\x00 \x00\x00\x05\xDC \x00\x00\x01\x00
const char *PCAP_HDR_TCPDUMP =
    "\xA1\xB2\xC3\xD4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\xDC\x00\x00\x01\x00";
const int PCAP_HDR_TCPDUMP_LEN = 24;
// const char* PCAP_FILE_NAME = "btle_store.pcap";
char *filename_pcap = NULL;
FILE *fh_pcap_store;

const uint8_t BTLE_HEADER_LEN = 10;

#define SAMPLE_PER_SYMBOL 4 // 4M sampling rate

volatile int rx_buf_offset; // remember to initialize it!

#define LEN_BUF_IN_SAMPLE                                                                                              \
    (4 * 4096) // 4096 samples = ~1ms for 4Msps; ATTENTION each rx callback get hackrf.c:lib_device->buffer_size
               // samples!!!
#define LEN_BUF (LEN_BUF_IN_SAMPLE * 2)
#define LEN_BUF_IN_SYMBOL (LEN_BUF_IN_SAMPLE / SAMPLE_PER_SYMBOL)

#define DEFAULT_CHANNEL 37
#define DEFAULT_ACCESS_ADDR (0x8E89BED6)
#define DEFAULT_CRC_INIT (0x555555)
#define MAX_CHANNEL_NUMBER 39
#define MAX_NUM_INFO_BYTE (43)
#define MAX_NUM_PHY_BYTE (47)
// #define MAX_NUM_PHY_SAMPLE ((MAX_NUM_PHY_BYTE*8*SAMPLE_PER_SYMBOL)+(LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL))
#define MAX_NUM_PHY_SAMPLE (MAX_NUM_PHY_BYTE * 8 * SAMPLE_PER_SYMBOL)
#define LEN_BUF_MAX_NUM_PHY_SAMPLE (2 * MAX_NUM_PHY_SAMPLE)

#define NUM_PREAMBLE_BYTE (1)
#define NUM_ACCESS_ADDR_BYTE (4)
#define NUM_PREAMBLE_ACCESS_BYTE (NUM_PREAMBLE_BYTE + NUM_ACCESS_ADDR_BYTE)
//----------------------------------BTLE SPEC related--------------------------------

static void print_usage(void);

volatile int8_t rx_buf[LEN_BUF + LEN_BUF_MAX_NUM_PHY_SAMPLE];

static void print_usage()
{
    printf("Usage:\n");
    printf("    -h --help\n");
    printf("      Print this help screen\n");
    printf("    -c --chan\n");
    printf("      Channel number. default 37. valid range 0~39\n");
    printf("    -g --gain\n");
    printf(
        "      Rx gain in dB. HACKRF rxvga default %d, valid 0~62. bladeRF default is max rx gain 66dB (valid 0~66)\n",
        DEFAULT_GAIN);
    printf("    -l --lnaGain\n");
    printf("      LNA gain in dB (HACKRF only). HACKRF lna default %d, valid 0~40.\n", 32);
    printf("    -b --amp\n");
    printf("      Enable amp (HACKRF only). Default off.\n");
    printf("    -a --access\n");
    printf("      Access address. 4 bytes. Hex format (like 89ABCDEF). Default %08x for channel 37 38 39. For other "
           "channel you should pick correct value according to sniffed link setup procedure\n",
           DEFAULT_ACCESS_ADDR);
    printf("    -k --crcinit\n");
    printf("      CRC init value. 3 bytes. Hex format (like 555555). Default %06x for channel 37 38 39. For other "
           "channel you should pick correct value according to sniffed link setup procedure\n",
           DEFAULT_CRC_INIT);
    printf("    -v --verbose\n");
    printf("      Print more information when there is error\n");
    printf("    -r --raw\n");
    printf("      Raw mode. After access addr is detected, print out following raw 42 bytes (without descrambling, "
           "parsing)\n");
    printf("    -f --freq_hz\n");
    printf("      This frequency (Hz) will override channel setting (In case someone want to work on freq other than "
           "BTLE. More general purpose)\n");
    printf("    -m --access_mask\n");
    printf(
        "      If a bit is 1 in this mask, corresponding bit in access address will be taken into packet existing "
        "decision (In case someone want a shorter/sparser unique word to do packet detection. More general purpose)\n");
    printf("    -o --hop\n");
    printf("      This will turn on data channel tracking (frequency hopping) after link setup information is captured "
           "in ADV_CONNECT_REQ packet\n");
    printf("    -s --filename\n");
    printf("      Store packets to pcap file.\n");
    printf("\nSee README for detailed information.\n");
}

typedef enum
{
    LL_RESERVED,
    LL_DATA1,
    LL_DATA2,
    LL_CTRL
} LL_PDU_TYPE;

char *LL_PDU_TYPE_STR[] = {"LL_RESERVED", "LL_DATA1", "LL_DATA2", "LL_CTRL"};

typedef struct
{
    uint8_t Data[40];
} LL_DATA_PDU_PAYLOAD_TYPE;

typedef enum
{
    LL_CONNECTION_UPDATE_REQ = 0,
    LL_CHANNEL_MAP_REQ = 1,
    LL_TERMINATE_IND = 2,
    LL_ENC_REQ = 3,
    LL_ENC_RSP = 4,
    LL_START_ENC_REQ = 5,
    LL_START_ENC_RSP = 6,
    LL_UNKNOWN_RSP = 7,
    LL_FEATURE_REQ = 8,
    LL_FEATURE_RSP = 9,
    LL_PAUSE_ENC_REQ = 10,
    LL_PAUSE_ENC_RSP = 11,
    LL_VERSION_IND = 12,
    LL_REJECT_IND = 13
} LL_CTRL_PDU_PAYLOAD_TYPE;

char *LL_CTRL_PDU_PAYLOAD_TYPE_STR[] = {
    "LL_CONNECTION_UPDATE_REQ", "LL_CHANNEL_MAP_REQ", "LL_TERMINATE_IND", "LL_ENC_REQ",     "LL_ENC_RSP",
    "LL_START_ENC_REQ",         "LL_START_ENC_RSP",   "LL_UNKNOWN_RSP",   "LL_FEATURE_REQ", "LL_FEATURE_RSP",
    "LL_PAUSE_ENC_REQ",         "LL_PAUSE_ENC_RSP",   "LL_VERSION_IND",   "LL_REJECT_IND",  "LL_RESERVED"};

typedef struct
{
    uint8_t Opcode;
    uint8_t WinSize;
    uint16_t WinOffset;
    uint16_t Interval;
    uint16_t Latency;
    uint16_t Timeout;
    uint16_t Instant;
} LL_CTRL_PDU_PAYLOAD_TYPE_0;

typedef struct
{
    uint8_t Opcode;
    uint8_t ChM[5];
    uint16_t Instant;
} LL_CTRL_PDU_PAYLOAD_TYPE_1;

typedef struct
{
    uint8_t Opcode;
    uint8_t ErrorCode;
} LL_CTRL_PDU_PAYLOAD_TYPE_2_7_13;

typedef struct
{
    uint8_t Opcode;
    uint8_t Rand[8];
    uint8_t EDIV[2];
    uint8_t SKDm[8];
    uint8_t IVm[4];
} LL_CTRL_PDU_PAYLOAD_TYPE_3;

typedef struct
{
    uint8_t Opcode;
    uint8_t SKDs[8];
    uint8_t IVs[4];
} LL_CTRL_PDU_PAYLOAD_TYPE_4;

typedef struct
{
    uint8_t Opcode;
} LL_CTRL_PDU_PAYLOAD_TYPE_5_6_10_11;

typedef struct
{
    uint8_t Opcode;
    uint8_t FeatureSet[8];
} LL_CTRL_PDU_PAYLOAD_TYPE_8_9;

typedef struct
{
    uint8_t Opcode;
    uint8_t VersNr;
    uint16_t CompId;
    uint16_t SubVersNr;
} LL_CTRL_PDU_PAYLOAD_TYPE_12;

typedef struct
{
    uint8_t Opcode;
    uint8_t payload_byte[40];
} LL_CTRL_PDU_PAYLOAD_TYPE_R;

typedef enum
{
    ADV_IND = 0,
    ADV_DIRECT_IND = 1,
    ADV_NONCONN_IND = 2,
    SCAN_REQ = 3,
    SCAN_RSP = 4,
    CONNECT_REQ = 5,
    ADV_SCAN_IND = 6,
    RESERVED0 = 7,
    RESERVED1 = 8,
    RESERVED2 = 9,
    RESERVED3 = 10,
    RESERVED4 = 11,
    RESERVED5 = 12,
    RESERVED6 = 13,
    RESERVED7 = 14,
    RESERVED8 = 15
} ADV_PDU_TYPE;

char *ADV_PDU_TYPE_STR[] = {"ADV_IND",   "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ",
                            "SCAN_RSP",  "CONNECT_REQ",    "ADV_SCAN_IND",    "RESERVED0",
                            "RESERVED1", "RESERVED2",      "RESERVED3",       "RESERVED4",
                            "RESERVED5", "RESERVED6",      "RESERVED7",       "RESERVED8"};

typedef struct
{
    uint8_t AdvA[6];
    uint8_t Data[31];
} ADV_PDU_PAYLOAD_TYPE_0_2_4_6;

typedef struct
{
    uint8_t A0[6];
    uint8_t A1[6];
} ADV_PDU_PAYLOAD_TYPE_1_3;

typedef struct
{
    uint8_t InitA[6];
    uint8_t AdvA[6];
    uint8_t AA[4];
    uint32_t CRCInit;
    uint8_t WinSize;
    uint16_t WinOffset;
    uint16_t Interval;
    uint16_t Latency;
    uint16_t Timeout;
    uint8_t ChM[5];
    uint8_t Hop;
    uint8_t SCA;
} ADV_PDU_PAYLOAD_TYPE_5;

typedef struct
{
    uint8_t payload_byte[40];
} ADV_PDU_PAYLOAD_TYPE_R;

//----------------------------------command line parameters----------------------------------
// Parse the command line arguments and return optional parameters as
// variables.
// Also performs some basic sanity checks on the parameters.
void parse_commandline(
    // Inputs
    int argc, char *const argv[],
    // Outputs
    int *chan, int *gain, int *lnaGain, uint8_t *amp, uint32_t *access_addr, uint32_t *crc_init, int *verbose_flag,
    int *raw_flag, uint64_t *freq_hz, uint32_t *access_mask, int *hop_flag, char **filename_pcap)
{
    printf("BLE sniffer. Xianjun Jiao. putaoshu@msn.com\n\n");

    // Default values
    (*chan) = DEFAULT_CHANNEL;

    (*gain) = DEFAULT_GAIN;

    (*lnaGain) = 32;

    (*amp) = 0;

    (*access_addr) = DEFAULT_ACCESS_ADDR;

    (*crc_init) = 0x555555;

    (*verbose_flag) = 0;

    (*raw_flag) = 0;

    (*freq_hz) = 123;

    (*access_mask) = 0xFFFFFFFF;

    (*hop_flag) = 0;

    (*filename_pcap) = 0;

    while (1)
    {
        static struct option long_options[] = {{"help", no_argument, 0, 'h'},
                                               {"chan", required_argument, 0, 'c'},
                                               {"gain", required_argument, 0, 'g'},
                                               {"lnaGain", required_argument, 0, 'l'},
                                               {"amp", no_argument, 0, 'b'},
                                               {"access", required_argument, 0, 'a'},
                                               {"crcinit", required_argument, 0, 'k'},
                                               {"verbose", no_argument, 0, 'v'},
                                               {"raw", no_argument, 0, 'r'},
                                               {"freq_hz", required_argument, 0, 'f'},
                                               {"access_mask", required_argument, 0, 'm'},
                                               {"hop", no_argument, 0, 'o'},
                                               {"filename", required_argument, 0, 's'},
                                               {0, 0, 0, 0}};
        /* getopt_long stores the option index here. */
        int option_index = 0;
        int c = getopt_long(argc, argv, "hc:g:l:ba:k:vrf:m:os:", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c)
        {
            char *endp;
        case 0:
            // Code should only get here if a long option was given a non-null
            // flag value.
            printf("Check code!\n");
            goto abnormal_quit;
            break;

        case 'v':
            (*verbose_flag) = 1;
            break;

        case 'r':
            (*raw_flag) = 1;
            break;

        case 'o':
            (*hop_flag) = 1;
            break;

        case 'h':
            goto abnormal_quit;
            break;

        case 'c':
            (*chan) = strtol(optarg, &endp, 10);
            break;

        case 'g':
            (*gain) = strtol(optarg, &endp, 10);
            break;

        case 'l':
            (*lnaGain) = strtol(optarg, &endp, 10);
            break;

        case 'b':
            (*amp) = 1;
            break;

        case 'f':
            (*freq_hz) = strtol(optarg, &endp, 10);
            break;

        case 'a':
            (*access_addr) = strtol(optarg, &endp, 16);
            break;

        case 'm':
            (*access_mask) = strtol(optarg, &endp, 16);
            break;

        case 'k':
            (*crc_init) = strtol(optarg, &endp, 16);
            break;

        case 's':
            (*filename_pcap) = (char *)optarg;
            break;

        case '?':
            /* getopt_long already printed an error message. */
            goto abnormal_quit;

        default:
            goto abnormal_quit;
        }
    }

    if ((*chan) < 0 || (*chan) > MAX_CHANNEL_NUMBER)
    {
        printf("channel number must be within 0~%d!\n", MAX_CHANNEL_NUMBER);
        goto abnormal_quit;
    }

    if ((*gain) < 0 || (*gain) > MAX_GAIN)
    {
        printf("rx gain must be within 0~%d!\n", MAX_GAIN);
        goto abnormal_quit;
    }

    if ((*lnaGain) < 0 || (*lnaGain) > 40)
    {
        printf("lna gain must be within 0~%d!\n", 40);
        goto abnormal_quit;
    }

    // Error if extra arguments are found on the command line
    if (optind < argc)
    {
        printf("Error: unknown/extra arguments specified on command line!\n");
        goto abnormal_quit;
    }

    return;

abnormal_quit:
    print_usage();
    exit(-1);
}
//----------------------------------command line parameters----------------------------------

//----------------------------------receiver----------------------------------
typedef struct
{
    int pkt_avaliable;
    int hop;
    int new_chm_flag;
    int interval;
    uint32_t access_addr;
    uint32_t crc_init;
    uint8_t chm[5];
    bool crc_ok;
} RECV_STATUS;

// #define LEN_DEMOD_BUF_PREAMBLE_ACCESS ( (NUM_PREAMBLE_ACCESS_BYTE*8)-8 ) // to get 2^x integer
// #define LEN_DEMOD_BUF_PREAMBLE_ACCESS 32
// #define LEN_DEMOD_BUF_PREAMBLE_ACCESS (NUM_PREAMBLE_ACCESS_BYTE*8)
#define LEN_DEMOD_BUF_ACCESS (NUM_ACCESS_ADDR_BYTE * 8) // 32 = 2^5

// static uint8_t demod_buf_preamble_access[SAMPLE_PER_SYMBOL][LEN_DEMOD_BUF_PREAMBLE_ACCESS];
static uint8_t demod_buf_access[SAMPLE_PER_SYMBOL][LEN_DEMOD_BUF_ACCESS];
// uint8_t preamble_access_byte[NUM_PREAMBLE_ACCESS_BYTE] = {0xAA, 0xD6, 0xBE, 0x89, 0x8E};
uint8_t access_byte[NUM_ACCESS_ADDR_BYTE] = {0xD6, 0xBE, 0x89, 0x8E};
// uint8_t preamble_access_bit[NUM_PREAMBLE_ACCESS_BYTE*8];
uint8_t access_bit[NUM_ACCESS_ADDR_BYTE * 8];
uint8_t access_bit_mask[NUM_ACCESS_ADDR_BYTE * 8];
uint8_t tmp_byte[2 + 37 + 3]; // header length + maximum payload length 37 + 3 octets CRC

RECV_STATUS receiver_status;

inline int search_unique_bits(int8_t *rxp, int search_len, uint8_t *unique_bits, uint8_t *unique_bits_mask,
                              const int num_bits)
{
    int i, sp, j, i0, q0, i1, q1, k, p, phase_idx;
    bool unequal_flag;
    const int demod_buf_len = num_bits;
    int demod_buf_offset = 0;

    // demod_buf_preamble_access[SAMPLE_PER_SYMBOL][LEN_DEMOD_BUF_PREAMBLE_ACCESS]
    // memset(demod_buf_preamble_access, 0, SAMPLE_PER_SYMBOL*LEN_DEMOD_BUF_PREAMBLE_ACCESS);
    memset(demod_buf_access, 0, SAMPLE_PER_SYMBOL * LEN_DEMOD_BUF_ACCESS);
    for (i = 0; i < search_len * SAMPLE_PER_SYMBOL * 2; i = i + (SAMPLE_PER_SYMBOL * 2))
    {
        sp = ((demod_buf_offset - demod_buf_len + 1) & (demod_buf_len - 1));
        // sp = (demod_buf_offset-demod_buf_len+1);
        // if (sp>=demod_buf_len)
        //   sp = sp - demod_buf_len;

        for (j = 0; j < (SAMPLE_PER_SYMBOL * 2); j = j + 2)
        {
            i0 = rxp[i + j];
            q0 = rxp[i + j + 1];
            i1 = rxp[i + j + 2];
            q1 = rxp[i + j + 3];

            phase_idx = j / 2;
            // demod_buf_preamble_access[phase_idx][demod_buf_offset] = (i0*q1 - i1*q0) > 0? 1: 0;
            demod_buf_access[phase_idx][demod_buf_offset] = (i0 * q1 - i1 * q0) > 0 ? 1 : 0;

            k = sp;
            unequal_flag = false;
            for (p = 0; p < demod_buf_len; p++)
            {
                // if (demod_buf_preamble_access[phase_idx][k] != unique_bits[p]) {
                if (demod_buf_access[phase_idx][k] != unique_bits[p] && unique_bits_mask[p])
                {
                    unequal_flag = true;
                    break;
                }
                k = ((k + 1) & (demod_buf_len - 1));
                // k = (k + 1);
                // if (k>=demod_buf_len)
                //   k = k - demod_buf_len;
            }

            if (unequal_flag == false)
            {
                return (i + j - (demod_buf_len - 1) * SAMPLE_PER_SYMBOL * 2);
            }
        }

        demod_buf_offset = ((demod_buf_offset + 1) & (demod_buf_len - 1));
        // demod_buf_offset  = (demod_buf_offset+1);
        // if (demod_buf_offset>=demod_buf_len)
        //   demod_buf_offset = demod_buf_offset - demod_buf_len;
    }

    return (-1);
}

int parse_adv_pdu_payload_byte(uint8_t *payload_byte, int num_payload_byte, ADV_PDU_TYPE pdu_type,
                               void *adv_pdu_payload)
{
    ADV_PDU_PAYLOAD_TYPE_0_2_4_6 *payload_type_0_2_4_6 = NULL;
    ADV_PDU_PAYLOAD_TYPE_1_3 *payload_type_1_3 = NULL;
    ADV_PDU_PAYLOAD_TYPE_5 *payload_type_5 = NULL;
    ADV_PDU_PAYLOAD_TYPE_R *payload_type_R = NULL;
    if (num_payload_byte < 6)
    {
        // payload_parse_result_str = ['Payload Too Short (only ' num2str(length(payload_bits)) ' bits)'];
        printf("Error: Payload Too Short (only %d bytes)!\n", num_payload_byte);
        return (-1);
    }

    if (pdu_type == ADV_IND || pdu_type == ADV_NONCONN_IND || pdu_type == SCAN_RSP || pdu_type == ADV_SCAN_IND)
    {
        payload_type_0_2_4_6 = (ADV_PDU_PAYLOAD_TYPE_0_2_4_6 *)adv_pdu_payload;

        // AdvA = reorder_bytes_str( payload_bytes(1 : (2*6)) );
        payload_type_0_2_4_6->AdvA[0] = payload_byte[5];
        payload_type_0_2_4_6->AdvA[1] = payload_byte[4];
        payload_type_0_2_4_6->AdvA[2] = payload_byte[3];
        payload_type_0_2_4_6->AdvA[3] = payload_byte[2];
        payload_type_0_2_4_6->AdvA[4] = payload_byte[1];
        payload_type_0_2_4_6->AdvA[5] = payload_byte[0];

        // AdvData = payload_bytes((2*6+1):end);
        // for(i=0; i<(num_payload_byte-6); i++) {
        //   payload_type_0_2_4_6->Data[i] = payload_byte[6+i];
        // }
        memcpy(payload_type_0_2_4_6->Data, payload_byte + 6, num_payload_byte - 6);

        // payload_parse_result_str = ['AdvA:' AdvA ' AdvData:' AdvData];
    }
    else if (pdu_type == ADV_DIRECT_IND || pdu_type == SCAN_REQ)
    {
        if (num_payload_byte != 12)
        {
            printf("Error: Payload length %d bytes. Need to be 12 for PDU Type %s!\n", num_payload_byte,
                   ADV_PDU_TYPE_STR[pdu_type]);
            return (-1);
        }
        payload_type_1_3 = (ADV_PDU_PAYLOAD_TYPE_1_3 *)adv_pdu_payload;

        // AdvA = reorder_bytes_str( payload_bytes(1 : (2*6)) );
        payload_type_1_3->A0[0] = payload_byte[5];
        payload_type_1_3->A0[1] = payload_byte[4];
        payload_type_1_3->A0[2] = payload_byte[3];
        payload_type_1_3->A0[3] = payload_byte[2];
        payload_type_1_3->A0[4] = payload_byte[1];
        payload_type_1_3->A0[5] = payload_byte[0];

        // InitA = reorder_bytes_str( payload_bytes((2*6+1):end) );
        payload_type_1_3->A1[0] = payload_byte[11];
        payload_type_1_3->A1[1] = payload_byte[10];
        payload_type_1_3->A1[2] = payload_byte[9];
        payload_type_1_3->A1[3] = payload_byte[8];
        payload_type_1_3->A1[4] = payload_byte[7];
        payload_type_1_3->A1[5] = payload_byte[6];

        // payload_parse_result_str = ['AdvA:' AdvA ' InitA:' InitA];
    }
    else if (pdu_type == CONNECT_REQ)
    {
        if (num_payload_byte != 34)
        {
            printf("Error: Payload length %d bytes. Need to be 34 for PDU Type %s!\n", num_payload_byte,
                   ADV_PDU_TYPE_STR[pdu_type]);
            return (-1);
        }
        payload_type_5 = (ADV_PDU_PAYLOAD_TYPE_5 *)adv_pdu_payload;

        // InitA = reorder_bytes_str( payload_bytes(1 : (2*6)) );
        payload_type_5->InitA[0] = payload_byte[5];
        payload_type_5->InitA[1] = payload_byte[4];
        payload_type_5->InitA[2] = payload_byte[3];
        payload_type_5->InitA[3] = payload_byte[2];
        payload_type_5->InitA[4] = payload_byte[1];
        payload_type_5->InitA[5] = payload_byte[0];

        // AdvA = reorder_bytes_str( payload_bytes((2*6+1):(2*6+2*6)) );
        payload_type_5->AdvA[0] = payload_byte[11];
        payload_type_5->AdvA[1] = payload_byte[10];
        payload_type_5->AdvA[2] = payload_byte[9];
        payload_type_5->AdvA[3] = payload_byte[8];
        payload_type_5->AdvA[4] = payload_byte[7];
        payload_type_5->AdvA[5] = payload_byte[6];

        // AA = reorder_bytes_str( payload_bytes((2*6+2*6+1):(2*6+2*6+2*4)) );
        payload_type_5->AA[0] = payload_byte[15];
        payload_type_5->AA[1] = payload_byte[14];
        payload_type_5->AA[2] = payload_byte[13];
        payload_type_5->AA[3] = payload_byte[12];

        // CRCInit = payload_bytes((2*6+2*6+2*4+1):(2*6+2*6+2*4+2*3));
        payload_type_5->CRCInit = (payload_byte[16]);
        payload_type_5->CRCInit = ((payload_type_5->CRCInit << 8) | payload_byte[17]);
        payload_type_5->CRCInit = ((payload_type_5->CRCInit << 8) | payload_byte[18]);

        // WinSize = payload_bytes((2*6+2*6+2*4+2*3+1):(2*6+2*6+2*4+2*3+2*1));
        payload_type_5->WinSize = payload_byte[19];

        // WinOffset = reorder_bytes_str( payload_bytes((2*6+2*6+2*4+2*3+2*1+1):(2*6+2*6+2*4+2*3+2*1+2*2)) );
        payload_type_5->WinOffset = (payload_byte[21]);
        payload_type_5->WinOffset = ((payload_type_5->WinOffset << 8) | payload_byte[20]);

        // Interval = reorder_bytes_str( payload_bytes((2*6+2*6+2*4+2*3+2*1+2*2+1):(2*6+2*6+2*4+2*3+2*1+2*2+2*2)) );
        payload_type_5->Interval = (payload_byte[23]);
        payload_type_5->Interval = ((payload_type_5->Interval << 8) | payload_byte[22]);

        // Latency = reorder_bytes_str( payload_bytes((2*6+2*6+2*4+2*3+2*1+2*2+2*2+1):(2*6+2*6+2*4+2*3+2*1+2*2+2*2+2*2))
        // );
        payload_type_5->Latency = (payload_byte[25]);
        payload_type_5->Latency = ((payload_type_5->Latency << 8) | payload_byte[24]);

        // Timeout = reorder_bytes_str(
        // payload_bytes((2*6+2*6+2*4+2*3+2*1+2*2+2*2+2*2+1):(2*6+2*6+2*4+2*3+2*1+2*2+2*2+2*2+2*2)) );
        payload_type_5->Timeout = (payload_byte[27]);
        payload_type_5->Timeout = ((payload_type_5->Timeout << 8) | payload_byte[26]);

        // ChM = reorder_bytes_str(
        // payload_bytes((2*6+2*6+2*4+2*3+2*1+2*2+2*2+2*2+2*2+1):(2*6+2*6+2*4+2*3+2*1+2*2+2*2+2*2+2*2+2*5)) );
        payload_type_5->ChM[0] = payload_byte[32];
        payload_type_5->ChM[1] = payload_byte[31];
        payload_type_5->ChM[2] = payload_byte[30];
        payload_type_5->ChM[3] = payload_byte[29];
        payload_type_5->ChM[4] = payload_byte[28];

        // tmp_bits = payload_bits((end-7) : end);
        // Hop = num2str( bi2de(tmp_bits(1:5), 'right-msb') );
        // SCA = num2str( bi2de(tmp_bits(6:end), 'right-msb') );
        payload_type_5->Hop = (payload_byte[33] & 0x1F);
        payload_type_5->SCA = ((payload_byte[33] >> 5) & 0x07);

        receiver_status.hop = payload_type_5->Hop;
        receiver_status.new_chm_flag = 1;
        receiver_status.interval = payload_type_5->Interval;

        receiver_status.access_addr = (payload_byte[15]);
        receiver_status.access_addr = ((receiver_status.access_addr << 8) | payload_byte[14]);
        receiver_status.access_addr = ((receiver_status.access_addr << 8) | payload_byte[13]);
        receiver_status.access_addr = ((receiver_status.access_addr << 8) | payload_byte[12]);

        receiver_status.crc_init = payload_type_5->CRCInit;

        receiver_status.chm[0] = payload_type_5->ChM[0];
        receiver_status.chm[1] = payload_type_5->ChM[1];
        receiver_status.chm[2] = payload_type_5->ChM[2];
        receiver_status.chm[3] = payload_type_5->ChM[3];
        receiver_status.chm[4] = payload_type_5->ChM[4];
    }
    else
    {
        payload_type_R = (ADV_PDU_PAYLOAD_TYPE_R *)adv_pdu_payload;

        // for(i=0; i<(num_payload_byte); i++) {
        //   payload_type_R->payload_byte[i] = payload_byte[i];
        // }
        memcpy(payload_type_R->payload_byte, payload_byte, num_payload_byte);

        // printf("Warning: Reserved PDU type %d\n", pdu_type);
        // return(-1);
    }

    return (0);
}

int parse_ll_pdu_payload_byte(uint8_t *payload_byte, int num_payload_byte, LL_PDU_TYPE pdu_type, void *ll_pdu_payload)
{
    int ctrl_pdu_type;
    LL_DATA_PDU_PAYLOAD_TYPE *data_payload = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_0 *ctrl_payload_type_0 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_1 *ctrl_payload_type_1 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_2_7_13 *ctrl_payload_type_2_7_13 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_3 *ctrl_payload_type_3 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_4 *ctrl_payload_type_4 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_5_6_10_11 *ctrl_payload_type_5_6_10_11 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_8_9 *ctrl_payload_type_8_9 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_12 *ctrl_payload_type_12 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_R *ctrl_payload_type_R = NULL;

    if (num_payload_byte == 0)
    {
        if (pdu_type == LL_RESERVED || pdu_type == LL_DATA1)
        {
            return (0);
        }
        else if (pdu_type == LL_DATA2 || pdu_type == LL_CTRL)
        {
            printf("Error: LL PDU TYPE%d(%s) should not have payload length 0!\n", pdu_type, LL_PDU_TYPE_STR[pdu_type]);
            return (-1);
        }
    }

    if (pdu_type == LL_RESERVED || pdu_type == LL_DATA1 || pdu_type == LL_DATA2)
    {
        data_payload = (LL_DATA_PDU_PAYLOAD_TYPE *)ll_pdu_payload;
        memcpy(data_payload->Data, payload_byte, num_payload_byte);
    }
    else if (pdu_type == LL_CTRL)
    {
        ctrl_pdu_type = payload_byte[0];
        if (ctrl_pdu_type == LL_CONNECTION_UPDATE_REQ)
        {
            if (num_payload_byte != 12)
            {
                printf("Error: LL CTRL PDU TYPE%d(%s) should have payload length 12!\n", ctrl_pdu_type,
                       LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
                return (-1);
            }

            ctrl_payload_type_0 = (LL_CTRL_PDU_PAYLOAD_TYPE_0 *)ll_pdu_payload;
            ctrl_payload_type_0->Opcode = ctrl_pdu_type;

            ctrl_payload_type_0->WinSize = payload_byte[1];

            ctrl_payload_type_0->WinOffset = (payload_byte[3]);
            ctrl_payload_type_0->WinOffset = ((ctrl_payload_type_0->WinOffset << 8) | payload_byte[2]);

            ctrl_payload_type_0->Interval = (payload_byte[5]);
            ctrl_payload_type_0->Interval = ((ctrl_payload_type_0->Interval << 8) | payload_byte[4]);

            ctrl_payload_type_0->Latency = (payload_byte[7]);
            ctrl_payload_type_0->Latency = ((ctrl_payload_type_0->Latency << 8) | payload_byte[6]);

            ctrl_payload_type_0->Timeout = (payload_byte[9]);
            ctrl_payload_type_0->Timeout = ((ctrl_payload_type_0->Timeout << 8) | payload_byte[8]);

            ctrl_payload_type_0->Instant = (payload_byte[11]);
            ctrl_payload_type_0->Instant = ((ctrl_payload_type_0->Instant << 8) | payload_byte[10]);

            receiver_status.interval = ctrl_payload_type_0->Interval;
        }
        else if (ctrl_pdu_type == LL_CHANNEL_MAP_REQ)
        {
            if (num_payload_byte != 8)
            {
                printf("Error: LL CTRL PDU TYPE%d(%s) should have payload length 8!\n", ctrl_pdu_type,
                       LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
                return (-1);
            }
            ctrl_payload_type_1 = (LL_CTRL_PDU_PAYLOAD_TYPE_1 *)ll_pdu_payload;
            ctrl_payload_type_1->Opcode = ctrl_pdu_type;

            ctrl_payload_type_1->ChM[0] = payload_byte[5];
            ctrl_payload_type_1->ChM[1] = payload_byte[4];
            ctrl_payload_type_1->ChM[2] = payload_byte[3];
            ctrl_payload_type_1->ChM[3] = payload_byte[2];
            ctrl_payload_type_1->ChM[4] = payload_byte[1];

            ctrl_payload_type_1->Instant = (payload_byte[7]);
            ctrl_payload_type_1->Instant = ((ctrl_payload_type_1->Instant << 8) | payload_byte[6]);

            receiver_status.new_chm_flag = 1;

            receiver_status.chm[0] = ctrl_payload_type_1->ChM[0];
            receiver_status.chm[1] = ctrl_payload_type_1->ChM[1];
            receiver_status.chm[2] = ctrl_payload_type_1->ChM[2];
            receiver_status.chm[3] = ctrl_payload_type_1->ChM[3];
            receiver_status.chm[4] = ctrl_payload_type_1->ChM[4];
        }
        else if (ctrl_pdu_type == LL_TERMINATE_IND || ctrl_pdu_type == LL_UNKNOWN_RSP || ctrl_pdu_type == LL_REJECT_IND)
        {
            if (num_payload_byte != 2)
            {
                printf("Error: LL CTRL PDU TYPE%d(%s) should have payload length 2!\n", ctrl_pdu_type,
                       LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
                return (-1);
            }
            ctrl_payload_type_2_7_13 = (LL_CTRL_PDU_PAYLOAD_TYPE_2_7_13 *)ll_pdu_payload;
            ctrl_payload_type_2_7_13->Opcode = ctrl_pdu_type;

            ctrl_payload_type_2_7_13->ErrorCode = payload_byte[1];
        }
        else if (ctrl_pdu_type == LL_ENC_REQ)
        {
            if (num_payload_byte != 23)
            {
                printf("Error: LL CTRL PDU TYPE%d(%s) should have payload length 23!\n", ctrl_pdu_type,
                       LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
                return (-1);
            }
            ctrl_payload_type_3 = (LL_CTRL_PDU_PAYLOAD_TYPE_3 *)ll_pdu_payload;
            ctrl_payload_type_3->Opcode = ctrl_pdu_type;

            ctrl_payload_type_3->Rand[0] = payload_byte[8];
            ctrl_payload_type_3->Rand[1] = payload_byte[7];
            ctrl_payload_type_3->Rand[2] = payload_byte[6];
            ctrl_payload_type_3->Rand[3] = payload_byte[5];
            ctrl_payload_type_3->Rand[4] = payload_byte[4];
            ctrl_payload_type_3->Rand[5] = payload_byte[3];
            ctrl_payload_type_3->Rand[6] = payload_byte[2];
            ctrl_payload_type_3->Rand[7] = payload_byte[1];

            ctrl_payload_type_3->EDIV[0] = payload_byte[10];
            ctrl_payload_type_3->EDIV[1] = payload_byte[9];

            ctrl_payload_type_3->SKDm[0] = payload_byte[18];
            ctrl_payload_type_3->SKDm[1] = payload_byte[17];
            ctrl_payload_type_3->SKDm[2] = payload_byte[16];
            ctrl_payload_type_3->SKDm[3] = payload_byte[15];
            ctrl_payload_type_3->SKDm[4] = payload_byte[14];
            ctrl_payload_type_3->SKDm[5] = payload_byte[13];
            ctrl_payload_type_3->SKDm[6] = payload_byte[12];
            ctrl_payload_type_3->SKDm[7] = payload_byte[11];

            ctrl_payload_type_3->IVm[0] = payload_byte[22];
            ctrl_payload_type_3->IVm[1] = payload_byte[21];
            ctrl_payload_type_3->IVm[2] = payload_byte[20];
            ctrl_payload_type_3->IVm[3] = payload_byte[19];
        }
        else if (ctrl_pdu_type == LL_ENC_RSP)
        {
            if (num_payload_byte != 13)
            {
                printf("Error: LL CTRL PDU TYPE%d(%s) should have payload length 13!\n", ctrl_pdu_type,
                       LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
                return (-1);
            }
            ctrl_payload_type_4 = (LL_CTRL_PDU_PAYLOAD_TYPE_4 *)ll_pdu_payload;
            ctrl_payload_type_4->Opcode = ctrl_pdu_type;

            ctrl_payload_type_4->SKDs[0] = payload_byte[8];
            ctrl_payload_type_4->SKDs[1] = payload_byte[7];
            ctrl_payload_type_4->SKDs[2] = payload_byte[6];
            ctrl_payload_type_4->SKDs[3] = payload_byte[5];
            ctrl_payload_type_4->SKDs[4] = payload_byte[4];
            ctrl_payload_type_4->SKDs[5] = payload_byte[3];
            ctrl_payload_type_4->SKDs[6] = payload_byte[2];
            ctrl_payload_type_4->SKDs[7] = payload_byte[1];

            ctrl_payload_type_4->IVs[0] = payload_byte[12];
            ctrl_payload_type_4->IVs[1] = payload_byte[11];
            ctrl_payload_type_4->IVs[2] = payload_byte[10];
            ctrl_payload_type_4->IVs[3] = payload_byte[9];
        }
        else if (ctrl_pdu_type == LL_START_ENC_REQ || ctrl_pdu_type == LL_START_ENC_RSP ||
                 ctrl_pdu_type == LL_PAUSE_ENC_REQ || ctrl_pdu_type == LL_PAUSE_ENC_RSP)
        {
            if (num_payload_byte != 1)
            {
                printf("Error: LL CTRL PDU TYPE%d(%s) should have payload length 1!\n", ctrl_pdu_type,
                       LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
                return (-1);
            }
            ctrl_payload_type_5_6_10_11 = (LL_CTRL_PDU_PAYLOAD_TYPE_5_6_10_11 *)ll_pdu_payload;
            ctrl_payload_type_5_6_10_11->Opcode = ctrl_pdu_type;
        }
        else if (ctrl_pdu_type == LL_FEATURE_REQ || ctrl_pdu_type == LL_FEATURE_RSP)
        {
            if (num_payload_byte != 9)
            {
                printf("Error: LL CTRL PDU TYPE%d(%s) should have payload length 9!\n", ctrl_pdu_type,
                       LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
                return (-1);
            }
            ctrl_payload_type_8_9 = (LL_CTRL_PDU_PAYLOAD_TYPE_8_9 *)ll_pdu_payload;
            ctrl_payload_type_8_9->Opcode = ctrl_pdu_type;

            ctrl_payload_type_8_9->FeatureSet[0] = payload_byte[8];
            ctrl_payload_type_8_9->FeatureSet[1] = payload_byte[7];
            ctrl_payload_type_8_9->FeatureSet[2] = payload_byte[6];
            ctrl_payload_type_8_9->FeatureSet[3] = payload_byte[5];
            ctrl_payload_type_8_9->FeatureSet[4] = payload_byte[4];
            ctrl_payload_type_8_9->FeatureSet[5] = payload_byte[3];
            ctrl_payload_type_8_9->FeatureSet[6] = payload_byte[2];
            ctrl_payload_type_8_9->FeatureSet[7] = payload_byte[1];
        }
        else if (ctrl_pdu_type == LL_VERSION_IND)
        {
            if (num_payload_byte != 6)
            {
                printf("Error: LL CTRL PDU TYPE%d(%s) should have payload length 6!\n", ctrl_pdu_type,
                       LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
                return (-1);
            }
            ctrl_payload_type_12 = (LL_CTRL_PDU_PAYLOAD_TYPE_12 *)ll_pdu_payload;
            ctrl_payload_type_12->Opcode = ctrl_pdu_type;

            ctrl_payload_type_12->VersNr = payload_byte[1];

            ctrl_payload_type_12->CompId = (payload_byte[3]);
            ctrl_payload_type_12->CompId = ((ctrl_payload_type_12->CompId << 8) | payload_byte[2]);

            ctrl_payload_type_12->SubVersNr = (payload_byte[5]);
            ctrl_payload_type_12->SubVersNr = ((ctrl_payload_type_12->SubVersNr << 8) | payload_byte[4]);
        }
        else
        {
            ctrl_payload_type_R = (LL_CTRL_PDU_PAYLOAD_TYPE_R *)ll_pdu_payload;
            ctrl_payload_type_R->Opcode = ctrl_pdu_type;
            memcpy(ctrl_payload_type_R->payload_byte, payload_byte + 1, num_payload_byte - 1);
        }
    }

    return (ctrl_pdu_type);
}

void parse_ll_pdu_header_byte(uint8_t *byte_in, LL_PDU_TYPE *llid, int *nesn, int *sn, int *md, int *payload_len)
{
    (*llid) = (LL_PDU_TYPE)(byte_in[0] & 0x03);
    (*nesn) = ((byte_in[0] & 0x04) != 0);
    (*sn) = ((byte_in[0] & 0x08) != 0);
    (*md) = ((byte_in[0] & 0x10) != 0);
    (*payload_len) = (byte_in[1] & 0x1F);
}

void parse_adv_pdu_header_byte(uint8_t *byte_in, ADV_PDU_TYPE *pdu_type, int *tx_add, int *rx_add, int *payload_len)
{
    //% pdy_type_str = {'ADV_IND', 'ADV_DIRECT_IND', 'ADV_NONCONN_IND', 'SCAN_REQ', 'SCAN_RSP', 'CONNECT_REQ',
    //'ADV_SCAN_IND', 'Reserved', 'Reserved', 'Reserved', 'Reserved', 'Reserved', 'Reserved', 'Reserved', 'Reserved'};
    // pdu_type = bi2de(bits(1:4), 'right-msb');
    (*pdu_type) = (ADV_PDU_TYPE)(byte_in[0] & 0x0F);
    //% disp(['   PDU Type: ' pdy_type_str{pdu_type+1}]);

    // tx_add = bits(7);
    //% disp(['     Tx Add: ' num2str(tx_add)]);
    (*tx_add) = ((byte_in[0] & 0x40) != 0);

    // rx_add = bits(8);
    //% disp(['     Rx Add: ' num2str(rx_add)]);
    (*rx_add) = ((byte_in[0] & 0x80) != 0);

    // payload_len = bi2de(bits(9:14), 'right-msb');
    (*payload_len) = (byte_in[1] & 0x3F);
}

void print_ll_pdu_payload(void *ll_pdu_payload, LL_PDU_TYPE pdu_type, int ctrl_pdu_type, int num_payload_byte,
                          bool crc_flag)
{
    int i;
    LL_DATA_PDU_PAYLOAD_TYPE *data_payload = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_0 *ctrl_payload_type_0 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_1 *ctrl_payload_type_1 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_2_7_13 *ctrl_payload_type_2_7_13 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_3 *ctrl_payload_type_3 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_4 *ctrl_payload_type_4 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_5_6_10_11 *ctrl_payload_type_5_6_10_11 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_8_9 *ctrl_payload_type_8_9 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_12 *ctrl_payload_type_12 = NULL;
    LL_CTRL_PDU_PAYLOAD_TYPE_R *ctrl_payload_type_R = NULL;

    if (num_payload_byte == 0)
    {
        printf("CRC%d\n", crc_flag);
        return;
    }

    if (pdu_type == LL_RESERVED || pdu_type == LL_DATA1 || pdu_type == LL_DATA2)
    {
        data_payload = (LL_DATA_PDU_PAYLOAD_TYPE *)ll_pdu_payload;
        // memcpy(data_payload->Data, payload_byte, num_payload_byte);
        printf("LL_Data:");
        for (i = 0; i < (num_payload_byte); i++)
        {
            printf("%02x", data_payload->Data[i]);
        }
    }
    else if (pdu_type == LL_CTRL)
    {
        if (ctrl_pdu_type == LL_CONNECTION_UPDATE_REQ)
        {
            ctrl_payload_type_0 = (LL_CTRL_PDU_PAYLOAD_TYPE_0 *)ll_pdu_payload;
            printf("Op%02x(%s) WSize:%02x WOffset:%04x Itrvl:%04x Ltncy:%04x Timot:%04x Inst:%04x",
                   ctrl_payload_type_0->Opcode, LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type],
                   ctrl_payload_type_0->WinSize, ctrl_payload_type_0->WinOffset, ctrl_payload_type_0->Interval,
                   ctrl_payload_type_0->Latency, ctrl_payload_type_0->Timeout, ctrl_payload_type_0->Instant);
        }
        else if (ctrl_pdu_type == LL_CHANNEL_MAP_REQ)
        {
            ctrl_payload_type_1 = (LL_CTRL_PDU_PAYLOAD_TYPE_1 *)ll_pdu_payload;
            printf("Op%02x(%s)", ctrl_payload_type_1->Opcode, LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
            printf(" ChM:");
            for (i = 0; i < 5; i++)
            {
                printf("%02x", ctrl_payload_type_1->ChM[i]);
            }
            printf(" Inst:%04x", ctrl_payload_type_1->Instant);
        }
        else if (ctrl_pdu_type == LL_TERMINATE_IND || ctrl_pdu_type == LL_UNKNOWN_RSP || ctrl_pdu_type == LL_REJECT_IND)
        {
            ctrl_payload_type_2_7_13 = (LL_CTRL_PDU_PAYLOAD_TYPE_2_7_13 *)ll_pdu_payload;
            printf("Op%02x(%s) Err:%02x", ctrl_payload_type_2_7_13->Opcode, LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type],
                   ctrl_payload_type_2_7_13->ErrorCode);
        }
        else if (ctrl_pdu_type == LL_ENC_REQ)
        {
            ctrl_payload_type_3 = (LL_CTRL_PDU_PAYLOAD_TYPE_3 *)ll_pdu_payload;
            printf("Op%02x(%s)", ctrl_payload_type_3->Opcode, LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
            printf(" Rand:");
            for (i = 0; i < 8; i++)
            {
                printf("%02x", ctrl_payload_type_3->Rand[i]);
            }
            printf(" EDIV:");
            for (i = 0; i < 2; i++)
            {
                printf("%02x", ctrl_payload_type_3->EDIV[i]);
            }
            printf(" SKDm:");
            for (i = 0; i < 8; i++)
            {
                printf("%02x", ctrl_payload_type_3->SKDm[i]);
            }
            printf(" IVm:");
            for (i = 0; i < 4; i++)
            {
                printf("%02x", ctrl_payload_type_3->IVm[i]);
            }
        }
        else if (ctrl_pdu_type == LL_ENC_RSP)
        {
            ctrl_payload_type_4 = (LL_CTRL_PDU_PAYLOAD_TYPE_4 *)ll_pdu_payload;
            printf("Op%02x(%s)", ctrl_payload_type_4->Opcode, LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
            printf(" SKDs:");
            for (i = 0; i < 8; i++)
            {
                printf("%02x", ctrl_payload_type_4->SKDs[i]);
            }
            printf(" IVs:");
            for (i = 0; i < 4; i++)
            {
                printf("%02x", ctrl_payload_type_4->IVs[i]);
            }
        }
        else if (ctrl_pdu_type == LL_START_ENC_REQ || ctrl_pdu_type == LL_START_ENC_RSP ||
                 ctrl_pdu_type == LL_PAUSE_ENC_REQ || ctrl_pdu_type == LL_PAUSE_ENC_RSP)
        {
            ctrl_payload_type_5_6_10_11 = (LL_CTRL_PDU_PAYLOAD_TYPE_5_6_10_11 *)ll_pdu_payload;
            printf("Op%02x(%s)", ctrl_payload_type_5_6_10_11->Opcode, LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
        }
        else if (ctrl_pdu_type == LL_FEATURE_REQ || ctrl_pdu_type == LL_FEATURE_RSP)
        {
            ctrl_payload_type_8_9 = (LL_CTRL_PDU_PAYLOAD_TYPE_8_9 *)ll_pdu_payload;
            printf("Op%02x(%s)", ctrl_payload_type_8_9->Opcode, LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
            printf(" FteurSet:");
            for (i = 0; i < 8; i++)
            {
                printf("%02x", ctrl_payload_type_8_9->FeatureSet[i]);
            }
        }
        else if (ctrl_pdu_type == LL_VERSION_IND)
        {
            ctrl_payload_type_12 = (LL_CTRL_PDU_PAYLOAD_TYPE_12 *)ll_pdu_payload;
            printf("Op%02x(%s) Ver:%02x CompId:%04x SubVer:%04x", ctrl_payload_type_12->Opcode,
                   LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type], ctrl_payload_type_12->VersNr,
                   ctrl_payload_type_12->CompId, ctrl_payload_type_12->SubVersNr);
        }
        else
        {
            if (ctrl_pdu_type > LL_REJECT_IND)
                ctrl_pdu_type = LL_REJECT_IND + 1;
            ctrl_payload_type_R = (LL_CTRL_PDU_PAYLOAD_TYPE_R *)ll_pdu_payload;
            printf("Op%02x(%s)", ctrl_payload_type_R->Opcode, LL_CTRL_PDU_PAYLOAD_TYPE_STR[ctrl_pdu_type]);
            printf(" Byte:");
            for (i = 0; i < (num_payload_byte - 1); i++)
            {
                printf("%02x", ctrl_payload_type_R->payload_byte[i]);
            }
        }
    }

    printf(" CRC%d\n", crc_flag);
}

void print_adv_pdu_payload(void *adv_pdu_payload, ADV_PDU_TYPE pdu_type, int payload_len, bool crc_flag)
{
    int i;
    ADV_PDU_PAYLOAD_TYPE_5 *adv_pdu_payload_5;
    ADV_PDU_PAYLOAD_TYPE_1_3 *adv_pdu_payload_1_3;
    ADV_PDU_PAYLOAD_TYPE_0_2_4_6 *adv_pdu_payload_0_2_4_6;
    ADV_PDU_PAYLOAD_TYPE_R *adv_pdu_payload_R;
    // print payload out
    if (pdu_type == ADV_IND || pdu_type == ADV_NONCONN_IND || pdu_type == SCAN_RSP || pdu_type == ADV_SCAN_IND)
    {
        adv_pdu_payload_0_2_4_6 = (ADV_PDU_PAYLOAD_TYPE_0_2_4_6 *)(adv_pdu_payload);
        printf("AdvA:");
        for (i = 0; i < 6; i++)
        {
            printf("%02x", adv_pdu_payload_0_2_4_6->AdvA[i]);
        }
        printf(" Data:");
        for (i = 0; i < (payload_len - 6); i++)
        {
            printf("%02x", adv_pdu_payload_0_2_4_6->Data[i]);
        }
    }
    else if (pdu_type == ADV_DIRECT_IND || pdu_type == SCAN_REQ)
    {
        adv_pdu_payload_1_3 = (ADV_PDU_PAYLOAD_TYPE_1_3 *)(adv_pdu_payload);
        printf("A0:");
        for (i = 0; i < 6; i++)
        {
            printf("%02x", adv_pdu_payload_1_3->A0[i]);
        }
        printf(" A1:");
        for (i = 0; i < 6; i++)
        {
            printf("%02x", adv_pdu_payload_1_3->A1[i]);
        }
    }
    else if (pdu_type == CONNECT_REQ)
    {
        adv_pdu_payload_5 = (ADV_PDU_PAYLOAD_TYPE_5 *)(adv_pdu_payload);
        printf("InitA:");
        for (i = 0; i < 6; i++)
        {
            printf("%02x", adv_pdu_payload_5->InitA[i]);
        }
        printf(" AdvA:");
        for (i = 0; i < 6; i++)
        {
            printf("%02x", adv_pdu_payload_5->AdvA[i]);
        }
        printf(" AA:");
        for (i = 0; i < 4; i++)
        {
            printf("%02x", adv_pdu_payload_5->AA[i]);
        }
        printf(" CRCInit:%06x WSize:%02x WOffset:%04x Itrvl:%04x Ltncy:%04x Timot:%04x", adv_pdu_payload_5->CRCInit,
               adv_pdu_payload_5->WinSize, adv_pdu_payload_5->WinOffset, adv_pdu_payload_5->Interval,
               adv_pdu_payload_5->Latency, adv_pdu_payload_5->Timeout);
        printf(" ChM:");
        for (i = 0; i < 5; i++)
        {
            printf("%02x", adv_pdu_payload_5->ChM[i]);
        }
        printf(" Hop:%d SCA:%d", adv_pdu_payload_5->Hop, adv_pdu_payload_5->SCA);
    }
    else
    {
        adv_pdu_payload_R = (ADV_PDU_PAYLOAD_TYPE_R *)(adv_pdu_payload);
        printf("Byte:");
        for (i = 0; i < (payload_len); i++)
        {
            printf("%02x", adv_pdu_payload_R->payload_byte[i]);
        }
    }
    printf(" CRC%d\n", crc_flag);
}

// demodulates and parses a packet
void receiver(int8_t *rxp_in, int buf_len, int channel_number, uint32_t access_addr, uint32_t crc_init,
              int verbose_flag, int raw_flag)
{
    static int pkt_count = 0;
    static ADV_PDU_PAYLOAD_TYPE_R adv_pdu_payload;
    static LL_DATA_PDU_PAYLOAD_TYPE ll_data_pdu_payload;
    static struct timeval time_current_pkt, time_pre_pkt;
    const int demod_buf_len = LEN_BUF_MAX_NUM_PHY_SAMPLE + (LEN_BUF / 2);

    ADV_PDU_TYPE adv_pdu_type;
    LL_PDU_TYPE ll_pdu_type;

    int8_t *rxp = rxp_in;
    int num_demod_byte, hit_idx, buf_len_eaten, adv_tx_add, adv_rx_add, ll_nesn, ll_sn, ll_md, payload_len, time_diff,
        ll_ctrl_pdu_type, i;
    int num_symbol_left = buf_len / (SAMPLE_PER_SYMBOL * 2); // 2 for IQ
    bool crc_flag;
    bool adv_flag = (channel_number == 37 || channel_number == 38 || channel_number == 39);

    if (pkt_count == 0)
    { // the 1st time run
        gettimeofday(&time_current_pkt, NULL);
        time_pre_pkt = time_current_pkt;
    }

    uint32_to_bit_array(access_addr, access_bit);
    buf_len_eaten = 0;
    while (1)
    {
        hit_idx = search_unique_bits(rxp, num_symbol_left, access_bit, access_bit_mask, LEN_DEMOD_BUF_ACCESS);
        if (hit_idx == -1)
        {
            break;
        }
        // pkt_count++;
        // printf("hit %d\n", hit_idx);

        // printf("%d %d %d %d %d %d %d %d\n", rxp[hit_idx+0], rxp[hit_idx+1], rxp[hit_idx+2], rxp[hit_idx+3],
        // rxp[hit_idx+4], rxp[hit_idx+5], rxp[hit_idx+6], rxp[hit_idx+7]);

        buf_len_eaten = buf_len_eaten + hit_idx;
        // printf("%d\n", buf_len_eaten);

        buf_len_eaten =
            buf_len_eaten + 8 * NUM_ACCESS_ADDR_BYTE * 2 * SAMPLE_PER_SYMBOL; // move to beginning of PDU header
        rxp = rxp_in + buf_len_eaten;

        if (raw_flag)
            num_demod_byte = 42;
        else
            num_demod_byte = 2; // PDU header has 2 octets

        buf_len_eaten = buf_len_eaten + 8 * num_demod_byte * 2 * SAMPLE_PER_SYMBOL;
        // if ( buf_len_eaten > buf_len ) {
        if (buf_len_eaten > demod_buf_len)
        {
            break;
        }

        demodulate_byte(rxp, num_demod_byte, tmp_byte, SAMPLE_PER_SYMBOL);

        if (!raw_flag)
            dewhitening_bytes(tmp_byte, num_demod_byte, whitening_tables[channel_number], tmp_byte);
        rxp = rxp_in + buf_len_eaten;
        num_symbol_left = (buf_len - buf_len_eaten) / (SAMPLE_PER_SYMBOL * 2);

        if (raw_flag)
        { // raw recv stop here
            pkt_count++;

            gettimeofday(&time_current_pkt, NULL);
            time_diff = TimevalDiff(&time_current_pkt, &time_pre_pkt);
            time_pre_pkt = time_current_pkt;

            printf("%ld.%06ld Pkt%d Ch%d AA:%08x ", time_current_pkt.tv_sec, time_current_pkt.tv_usec, pkt_count,
                   channel_number, access_addr);
            printf("Raw:");
            for (i = 0; i < 42; i++)
            {
                printf("%02x", tmp_byte[i]);
            }
            printf("\n");

            continue;
        }

        if (adv_flag)
        {
            parse_adv_pdu_header_byte(tmp_byte, &adv_pdu_type, &adv_tx_add, &adv_rx_add, &payload_len);
            if (payload_len < 6 || payload_len > 37)
            {
                if (verbose_flag)
                {
                    printf("XXXus PktBAD Ch%d AA:%08x ", channel_number, access_addr);
                    printf("ADV_PDU_t%d:%s T%d R%d PloadL%d ", adv_pdu_type, ADV_PDU_TYPE_STR[adv_pdu_type], adv_tx_add,
                           adv_rx_add, payload_len);
                    printf("Error: ADV payload length should be 6~37!\n");
                }
                continue;
            }
        }
        else
        {
            parse_ll_pdu_header_byte(tmp_byte, &ll_pdu_type, &ll_nesn, &ll_sn, &ll_md, &payload_len);
        }

        // num_pdu_payload_crc_bits = (payload_len+3)*8;
        num_demod_byte = (payload_len + 3);
        buf_len_eaten = buf_len_eaten + 8 * num_demod_byte * 2 * SAMPLE_PER_SYMBOL;
        // if ( buf_len_eaten > buf_len ) {
        if (buf_len_eaten > demod_buf_len)
        {
            // printf("\n");
            break;
        }

        demodulate_byte(rxp, num_demod_byte, tmp_byte + 2, SAMPLE_PER_SYMBOL);
        dewhitening_bytes(tmp_byte + 2, num_demod_byte, whitening_tables[channel_number] + 2, tmp_byte + 2);
        rxp = rxp_in + buf_len_eaten;
        num_symbol_left = (buf_len - buf_len_eaten) / (SAMPLE_PER_SYMBOL * 2);

        crc_flag = crc_check(tmp_byte, payload_len + 2, crc_init);
        pkt_count++;
        receiver_status.pkt_avaliable = 1;
        receiver_status.crc_ok = (crc_flag == 0);

        gettimeofday(&time_current_pkt, NULL);
        time_diff = TimevalDiff(&time_current_pkt, &time_pre_pkt);
        time_pre_pkt = time_current_pkt;

        printf("%07dus Pkt%03d Ch%d AA:%08x ", time_diff, pkt_count, channel_number, access_addr);
        // if (filename_pcap != NULL)
        // write_packet_to_file(fh_pcap_store, BTLE_HEADER_LEN, payload_len + 2, tmp_byte, channel_number, access_addr,
        // fh_pcap_store);

        if (adv_flag)
        {
            printf("ADV_PDU_t%d:%s T%d R%d PloadL%d ", adv_pdu_type, ADV_PDU_TYPE_STR[adv_pdu_type], adv_tx_add,
                   adv_rx_add, payload_len);

            if (parse_adv_pdu_payload_byte(tmp_byte + 2, payload_len, adv_pdu_type, (void *)(&adv_pdu_payload)) != 0)
            {
                continue;
            }
            print_adv_pdu_payload((void *)(&adv_pdu_payload), adv_pdu_type, payload_len, crc_flag);
        }
        else
        {
            printf("LL_PDU_t%d:%s NESN%d SN%d MD%d PloadL%d ", ll_pdu_type, LL_PDU_TYPE_STR[ll_pdu_type], ll_nesn,
                   ll_sn, ll_md, payload_len);

            if ((ll_ctrl_pdu_type = parse_ll_pdu_payload_byte(tmp_byte + 2, payload_len, ll_pdu_type,
                                                              (void *)(&ll_data_pdu_payload))) < 0)
            {
                continue;
            }
            print_ll_pdu_payload((void *)(&ll_data_pdu_payload), ll_pdu_type, ll_ctrl_pdu_type, payload_len, crc_flag);
        }
    }
}
//----------------------------------receiver----------------------------------

//---------------------handle freq hop for channel mapping 1FFFFFFFFF--------------------

// state machine
int receiver_controller(void *rf_dev, int verbose_flag, int *chan, uint32_t *access_addr, uint32_t *crc_init_internal)
{
    const int guard_us = 7000;
    const int guard_us1 = 4000;
    static int hop_chan = 0;
    static int state = 0;
    static int interval_us, target_us, target_us1, hop;
    static struct timeval time_run, time_mark;
    uint64_t freq_hz;

    switch (state)
    {
    case 0: // wait for track
        if (receiver_status.crc_ok && receiver_status.hop != -1)
        { // start track unless you ctrl+c

            if (!chm_is_full_map(receiver_status.chm))
            {
                printf("Hop: Not full ChnMap 1FFFFFFFFF! (%02x%02x%02x%02x%02x) Stay in ADV Chn\n",
                       receiver_status.chm[0], receiver_status.chm[1], receiver_status.chm[2], receiver_status.chm[3],
                       receiver_status.chm[4]);
                receiver_status.hop = -1;
                return (0);
            }

            printf("Hop: track start ...\n");

            hop = receiver_status.hop;
            interval_us = receiver_status.interval * 1250;
            target_us = interval_us - guard_us;
            target_us1 = interval_us - guard_us1;

            hop_chan = ((hop_chan + hop) % 37);
            (*chan) = hop_chan;
            freq_hz = get_freq_by_channel_number(hop_chan);

            if (board_set_freq(rf_dev, freq_hz) != 0)
            {
                return (-1);
            }

            (*crc_init_internal) = crc_init_reorder(receiver_status.crc_init);
            (*access_addr) = receiver_status.access_addr;

            printf("Hop: next ch %d freq %ldMHz access %08x crcInit %06x\n", hop_chan, freq_hz / 1000000,
                   receiver_status.access_addr, receiver_status.crc_init);

            state = 1;
            printf("Hop: next state %d\n", state);
        }
        receiver_status.crc_ok = false;

        break;

    case 1: // wait for the 1st packet in data channel
        if (receiver_status.crc_ok)
        { // we capture the 1st data channel packet
            gettimeofday(&time_mark, NULL);
            printf("Hop: 1st data pdu\n");
            state = 2;
            printf("Hop: next state %d\n", state);
        }
        receiver_status.crc_ok = false;

        break;

    case 2: // wait for time is up. let hop to next chan
        gettimeofday(&time_run, NULL);
        if (TimevalDiff(&time_run, &time_mark) > target_us)
        { // time is up. let's hop

            gettimeofday(&time_mark, NULL);

            hop_chan = ((hop_chan + hop) % 37);
            (*chan) = hop_chan;
            freq_hz = get_freq_by_channel_number(hop_chan);

            if (board_set_freq(rf_dev, freq_hz) != 0)
            {
                return (-1);
            }

            if (verbose_flag)
                printf("Hop: next ch %d freq %ldMHz\n", hop_chan, freq_hz / 1000000);

            state = 3;
            if (verbose_flag)
                printf("Hop: next state %d\n", state);
        }
        receiver_status.crc_ok = false;

        break;

    case 3: // wait for the 1st packet in new data channel
        if (receiver_status.crc_ok)
        { // we capture the 1st data channel packet in new data channel
            gettimeofday(&time_mark, NULL);
            state = 2;
            if (verbose_flag)
                printf("Hop: next state %d\n", state);
        }

        gettimeofday(&time_run, NULL);
        if (TimevalDiff(&time_run, &time_mark) > target_us1)
        {
            if (verbose_flag)
                printf("Hop: skip\n");

            gettimeofday(&time_mark, NULL);

            hop_chan = ((hop_chan + hop) % 37);
            (*chan) = hop_chan;
            freq_hz = get_freq_by_channel_number(hop_chan);

            if (board_set_freq(rf_dev, freq_hz) != 0)
            {
                return (-1);
            }

            if (verbose_flag)
                printf("Hop: next ch %d freq %ldMHz\n", hop_chan, freq_hz / 1000000);

            if (verbose_flag)
                printf("Hop: next state %d\n", state);
        }

        receiver_status.crc_ok = false;
        break;

    default:
        printf("Hop: unknown state!\n");
        return (-1);
    }

    return (0);
}

int main(int argc, char **argv)
{
    uint64_t freq_hz;
    int gain, lnaGain, chan, phase, rx_buf_offset_tmp, verbose_flag, raw_flag, hop_flag;
    uint8_t amp;
    uint32_t access_addr, access_addr_mask, crc_init, crc_init_internal;
    bool run_flag = false;
    void *rf_dev;
    int8_t *rxp;

    hackrf_rx_context ctx;
    ctx.rx_buf = rx_buf;
    ctx.len_buf = LEN_BUF;
    ctx.rx_buf_offset = 0;

    parse_commandline(argc, argv, &chan, &gain, &lnaGain, &amp, &access_addr, &crc_init, &verbose_flag, &raw_flag,
                      &freq_hz, &access_addr_mask, &hop_flag, &filename_pcap);

    if (freq_hz == 123)
        freq_hz = get_freq_by_channel_number(chan);

    uint32_to_bit_array(access_addr_mask, access_bit_mask);

    printf("Cmd line input: chan %d, freq %ldMHz, access addr %08x, crc init %06x raw %d verbose %d rx %ddB (%s) "
           "file=%s\n",
           chan, freq_hz / 1000000, access_addr, crc_init, raw_flag, verbose_flag, gain, board_name, filename_pcap);

    // if (filename_pcap != NULL)
    // {
    //     printf("will store packets to: %s\n", filename_pcap);
    //     init_pcap_file(filename_pcap, fh_pcap_store, PCAP_HDR_TCPDUMP, PCAP_HDR_TCPDUMP_LEN);
    // }

    // run cyclic recv in background
    set_exit_status(false);
    if (config_run_board(freq_hz, gain, lnaGain, amp, SAMPLE_PER_SYMBOL, & rf_dev, &ctx) != 0)
    {
        if (rf_dev != NULL)
        {
            goto program_quit;
        }
        else
        {
            return (1);
        }
    }

    rx_buf_offset = ctx.rx_buf_offset;

    // init receiver
    receiver_status.pkt_avaliable = 0;
    receiver_status.hop = -1;
    receiver_status.new_chm_flag = 0;
    receiver_status.interval = 0;
    receiver_status.access_addr = 0;
    receiver_status.crc_init = 0;
    receiver_status.chm[0] = 0;
    receiver_status.chm[1] = 0;
    receiver_status.chm[2] = 0;
    receiver_status.chm[3] = 0;
    receiver_status.chm[4] = 0;
    receiver_status.crc_ok = false;

    crc_init_internal = crc_init_reorder(crc_init);

    // scan
    set_exit_status(false);
    phase = 0;
    rx_buf_offset = 0;
    while (get_exit_status() == false)
    { // hackrf_is_streaming(hackrf_dev) == HACKRF_TRUE?
        /*
        if ( (rx_buf_offset-rx_buf_offset_old) > 65536 || (rx_buf_offset-rx_buf_offset_old) < -65536 ) {
          printf("%d\n", rx_buf_offset);
          rx_buf_offset_old = rx_buf_offset;
        }
         * */
        // total buf len LEN_BUF = (8*4096)*2 =  (~ 8ms); tail length MAX_NUM_PHY_SAMPLE*2=LEN_BUF_MAX_NUM_PHY_SAMPLE

        rx_buf_offset_tmp = rx_buf_offset - LEN_BUF_MAX_NUM_PHY_SAMPLE;
        // cross point 0
        if (rx_buf_offset_tmp >= 0 && rx_buf_offset_tmp < (LEN_BUF / 2) && phase == 1)
        {
            // printf("rx_buf_offset cross 0: %d %d %d\n", rx_buf_offset, (LEN_BUF/2), LEN_BUF_MAX_NUM_PHY_SAMPLE);
            phase = 0;

            memcpy((void *)(rx_buf + LEN_BUF), (void *)rx_buf, LEN_BUF_MAX_NUM_PHY_SAMPLE * sizeof(int8_t));
            rxp = (int8_t *)(rx_buf + (LEN_BUF / 2));
            run_flag = true;
        }

        // cross point 1
        if (rx_buf_offset_tmp >= (LEN_BUF / 2) && phase == 0)
        {
            // printf("rx_buf_offset cross 1: %d %d %d\n", rx_buf_offset, (LEN_BUF/2), LEN_BUF_MAX_NUM_PHY_SAMPLE);
            phase = 1;

            rxp = (int8_t *)rx_buf;
            run_flag = true;
        }

        if (run_flag)
        {
#if 0
      // ------------------------for offline test -------------------------------------
      //save_phy_sample(rx_buf+buf_sp, LEN_BUF/2, "/home/jxj/git/BTLE/matlab/sample_iq_4msps.txt");
      load_phy_sample(tmp_buf, 2097152, "/home/jxj/git/BTLE/matlab/sample_iq_4msps.txt");
      receiver(tmp_buf, 2097152, 37, 0x8E89BED6, 0x555555, 1, 0);
      break;
      // ------------------------for offline test -------------------------------------
#endif

            // -----------------------------real online run--------------------------------
            // receiver(rxp, LEN_BUF_MAX_NUM_PHY_SAMPLE+(LEN_BUF/2), chan);
            receiver(rxp, (LEN_DEMOD_BUF_ACCESS - 1) * 2 * SAMPLE_PER_SYMBOL + (LEN_BUF) / 2, chan, access_addr,
                     crc_init_internal, verbose_flag, raw_flag);
            fflush(stdout);
            // -----------------------------real online run--------------------------------

            if (hop_flag)
            {
                if (receiver_controller(rf_dev, verbose_flag, &chan, &access_addr, &crc_init_internal) != 0)
                    goto program_quit;
            }

            run_flag = false;
        }
    }

program_quit:
    printf("Exit main loop ...\n");
    stop_close_board(rf_dev);

    if (fh_pcap_store)
        fclose(fh_pcap_store);
    return (0);
}
