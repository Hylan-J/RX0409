#include "utils/data_rw.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void save_phy_sample(int8_t *IQ_sample, int num_IQ_sample, char *filename)
{
    int i;

    FILE *fp = fopen(filename, "w");
    if (fp == NULL)
    {
        printf("save_phy_sample: fopen failed!\n");
        return;
    }

    for (i = 0; i < num_IQ_sample; i++)
    {
        if (i % 64 == 0)
        {
            fprintf(fp, "\n");
        }
        fprintf(fp, "%d, ", IQ_sample[i]);
    }
    fprintf(fp, "\n");

    fclose(fp);
}

void load_phy_sample(int8_t *IQ_sample, int num_IQ_sample, char *filename)
{
    int i, tmp_val;

    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        printf("load_phy_sample: fopen failed!\n");
        return;
    }

    i = 0;
    while (~feof(fp))
    {
        if (fscanf(fp, "%d,", &tmp_val))
        {
            IQ_sample[i] = tmp_val;
            i++;
        }
        if (num_IQ_sample != -1)
        {
            if (i == num_IQ_sample)
            {
                break;
            }
        }
        // printf("%d\n", i);
    }
    printf("%d I/Q are read.\n", i);

    fclose(fp);
}

void save_phy_sample_for_matlab(int8_t *IQ_sample, int num_IQ_sample, char *filename)
{
    int i;

    FILE *fp = fopen(filename, "w");
    if (fp == NULL)
    {
        printf("save_phy_sample_for_matlab: fopen failed!\n");
        return;
    }

    for (i = 0; i < num_IQ_sample; i++)
    {
        if (i % 64 == 0)
        {
            fprintf(fp, "...\n");
        }
        fprintf(fp, "%d ", IQ_sample[i]);
    }
    fprintf(fp, "\n");

    fclose(fp);
}

void init_pcap_file(char *filename_pcap, FILE *fh_pcap_store, const char *pcap_hdr_tcpdump,
                    const int pcap_hdr_tcpdump_len)
{
    fh_pcap_store = fopen(filename_pcap, "wb");
    fwrite(pcap_hdr_tcpdump, 1, pcap_hdr_tcpdump_len, fh_pcap_store);
}

void write_packet_to_file(FILE *fh, const uint8_t BTLE_HEADER_LEN, int packet_len, uint8_t *packet, uint8_t channel,
                          uint32_t access_addr, FILE *fh_pcap_store)
{
    // flags: 0x0001 indicates the LE Packet is de-whitened
    // pcap header: tv_sec tv_usec caplen len
    pcap_header header_pcap;
    // header_pcap.sec = packetcount++;
    header_pcap.caplen = htonl(BTLE_HEADER_LEN + 4 + packet_len);
    header_pcap.len = htonl(BTLE_HEADER_LEN + 4 + packet_len);
    fwrite(&header_pcap, 16, 1, fh_pcap_store);
    // BTLE header: RF_Channel:1 Signal_Power:1 Noise_Power:1 Access_address_off:1 Reference_access_address (receiver):4
    // flags:2 packet
    uint8_t header_btle[10] = {channel, 0, 0, 0, 0, 0, 0, 0, 1, 0};
    fwrite(header_btle, 1, 10, fh);
    fwrite(&access_addr, 1, 4, fh);
    fwrite(packet, 1, packet_len, fh);
}
void write_dummy_entry(FILE *fh_pcap_store)
{
    uint8_t pkt[10] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
    write_packet_to_file(fh_pcap_store, 10, pkt, 1, 0xFFFFFFF1);
    write_packet_to_file(fh_pcap_store, 10, pkt, 2, 0xFFFFFFF2);
    write_packet_to_file(fh_pcap_store, 10, pkt, 3, 0xFFFFFFF3);
}