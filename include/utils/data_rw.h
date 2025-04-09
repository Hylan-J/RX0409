#ifndef DATA_RW_H
#define DATA_RW_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void save_phy_sample(int8_t *IQ_sample, int num_IQ_sample, char *filename);

void load_phy_sample(int8_t *IQ_sample, int num_IQ_sample, char *filename);

void save_phy_sample_for_matlab(int8_t *IQ_sample, int num_IQ_sample, char *filename);

void init_pcap_file(char *filename_pcap, FILE *fh_pcap_store, const char *pcap_hdr_tcpdump,
                    const int pcap_hdr_tcpdump_len);

typedef struct
{
    int sec;
    int usec;
    int caplen;
    int len;
} pcap_header;

void write_packet_to_file(FILE *fh, const uint8_t BTLE_HEADER_LEN, int packet_len, uint8_t *packet, uint8_t channel,
                          uint32_t access_addr, FILE *fh_pcap_store);
void write_dummy_entry(FILE *fh_pcap_store);

#endif // DATA_RW_H