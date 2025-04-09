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