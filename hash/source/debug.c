#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../headers/hash_3411.h"

#define p(t) printf("%s ", t);
void printle(uint8_t* a, int len)
{
    printf("0x");
    for (int i = len-1; i >= 0; i--)
        printf("%s%hhx", (a[i]<0x10) ? "0" : "", a[i]);
    printf("\n");
}

void hash_file(const char* fname)
{
    //hash_generate_512_append(msg1, 20, 0);
    //uint8_t* h2 = NULL; //= hash_generate_512_append(msg1+20, 63-20, 1);
    //p(" hash 512:") printle(h2, 64);
    //p(" real 512:") printle(r1, 64);

    //free(h2);

    uint8_t* h = NULL;
    FILE* fi = fopen(fname, "rb");

    size_t buffer_size = 1024*1024;
    uint8_t* buffer = (uint8_t*)malloc(buffer_size*sizeof(uint8_t));
    while (fread(buffer, sizeof(uint8_t), buffer_size, fi) > 0)
    {
        hash_generate_512_append(buffer, buffer_size, 0);
    }

    h = hash_generate_512_append(NULL, 0, 1);
    p(" hash 512:") printle(h, 64);
    //p(" real 512:") printle(r3, 64);

    free(h);
    return;

}

int main(int argc, char** argv)
{
    if (argc > 1)
    {
        hash_file(argv[1]);
        return 0;
    }

    uint8_t msg1[63] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, 0x32
    };
    uint8_t msg2[72] = {
        0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2, 0xf0, 0xe8, 0x2c, 0x20,
        0xd1, 0xf2, 0xf0, 0xe8, 0xe1, 0xee, 0xe6, 0xe8, 0x20, 0xe2,
        0xed, 0xf3, 0xf6, 0xe8, 0x2c, 0x20, 0xe2, 0xe5, 0xfe, 0xf2,
        0xfa, 0x20, 0xf1, 0x20, 0xec, 0xee, 0xf0, 0xff, 0x20, 0xf1,
        0xf2, 0xf0, 0xe5, 0xeb, 0xe0, 0xec, 0xe8, 0x20, 0xed, 0xe0,
        0x20, 0xf5, 0xf0, 0xe0, 0xe1, 0xf0, 0xfb, 0xff, 0x20, 0xef,
        0xeb, 0xfa, 0xea, 0xfb, 0x20, 0xc8, 0xe3, 0xee, 0xf0, 0xe5,
        0xe2, 0xfb
    };
    uint8_t r1[64] = { //from msg1, 512 bit
        0x1b, 0x54, 0xd0, 0x1a, 0x4a, 0xf5, 0xb9, 0xd5, 0xcc, 0x3d,
        0x86, 0xd6, 0x8d, 0x28, 0x54, 0x62, 0xb1, 0x9a, 0xbc, 0x24,
        0x75, 0x22, 0x2f, 0x35, 0xc0, 0x85, 0x12, 0x2b, 0xe4, 0xba,
        0x1f, 0xfa, 0x00, 0xad, 0x30, 0xf8, 0x76, 0x7b, 0x3a, 0x82,
        0x38, 0x4c, 0x65, 0x74, 0xf0, 0x24, 0xc3, 0x11, 0xe2, 0xa4,
        0x81, 0x33, 0x2b, 0x08, 0xef, 0x7f, 0x41, 0x79, 0x78, 0x91,
        0xc1, 0x64, 0x6f, 0x48
    };
    uint8_t r2[32] = { //from msg1, 256 bit
        0x9d, 0x15, 0x1e, 0xef, 0xd8, 0x59, 0x0b, 0x89, 0xda, 0xa6,
        0xba, 0x6c, 0xb7, 0x4a, 0xf9, 0x27, 0x5d, 0xd0, 0x51, 0x02,
        0x6b, 0xb1, 0x49, 0xa4, 0x52, 0xfd, 0x84, 0xe5, 0xe5, 0x7b,
        0x55, 0x00
    };
    uint8_t r3[64] = { //from msg2, 512 bit
        0x1e, 0x88, 0xe6, 0x22, 0x26, 0xbf, 0xca, 0x6f, 0x99, 0x94,
        0xf1, 0xf2, 0xd5, 0x15, 0x69, 0xe0, 0xda, 0xf8, 0x47, 0x5a,
        0x3b, 0x0f, 0xe6, 0x1a, 0x53, 0x00, 0xee, 0xe4, 0x6d, 0x96,
        0x13, 0x76, 0x03, 0x5f, 0xe8, 0x35, 0x49, 0xad, 0xa2, 0xb8,
        0x62, 0x0f, 0xcd, 0x7c, 0x49, 0x6c, 0xe5, 0xb3, 0x3f, 0x0c,
        0xb9, 0xdd, 0xdc, 0x2b, 0x64, 0x60, 0x14, 0x3b, 0x03, 0xda,
        0xba, 0xc9, 0xfb, 0x28
    };
    uint8_t r4[32] = { //from msg2, 256 bit
        0x9d, 0xd2, 0xfe, 0x4e, 0x90, 0x40, 0x9e, 0x5d, 0xa8, 0x7f,
        0x53, 0x97, 0x6d, 0x74, 0x05, 0xb0, 0xc0, 0xca, 0xc6, 0x28,
        0xfc, 0x66, 0x9a, 0x74, 0x1d, 0x50, 0x06, 0x3c, 0x55, 0x7e,
        0x8f, 0x50
    };

    printf("hash test:\n");

    p("plain:") printle(msg1, 63);
    uint8_t* h1 = hash_generate_256_append(msg1, 20, 0);
    h1 = hash_generate_256_append(msg1+20, 63-20, 1);
    p(" hash 256:") printle(h1, 32);
    p(" real 256:") printle(r2, 32);
/*
    uint8_t* h2 = hash_generate_256(msg1, 63);
    p(" hash 256:") printle(h2, 32);
    p(" real 256:") printle(r2, 32);*/

    hash_generate_512_append(msg1, 20, 0);
    uint8_t* h2 = hash_generate_512_append(msg1+20, 63-20, 1);
    p(" hash 512:") printle(h2, 64);
    p(" real 512:") printle(r1, 64);

    free(h1); free(h2);

    p("\nplain:") printle(msg2, 72);
    hash_generate_256_append(msg2, 66, 0);
    h1 = hash_generate_256_append(msg2+66, 6, 1);
    p(" hash 256:") printle(h1, 32);
    p(" real 256:") printle(r4, 32);

    hash_generate_512_append(msg2, 22, 0);
    hash_generate_512_append(msg2+22, 44, 0);
    h2 = hash_generate_512_append(msg2+66, 6, 0);
    h2 = hash_generate_512_append(NULL, 0, 1);
    p(" hash 512:") printle(h2, 64);
    p(" real 512:") printle(r3, 64);

    free(h1); free(h2);

    printf("\n\nhmac test:\n");

    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f
    };

    uint8_t msg[16] = {
        0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21, 0x43, 0x41,
        0x45, 0x65, 0x63, 0x78, 0x01, 0x00
    };

    uint8_t res256[32] = {
        0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23,
        0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34, 0x01, 0x31, 0x37, 0x01,
        0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92,
        0x2e, 0xd9
    };

    uint8_t res512[64] = {
        0xa5, 0x9b, 0xab, 0x22, 0xec, 0xae, 0x19, 0xc6, 0x5f, 0xbd,
        0xe6, 0xe5, 0xf4, 0xe9, 0xf5, 0xd8, 0x54, 0x9d, 0x31, 0xf0,
        0x37, 0xf9, 0xdf, 0x9b, 0x90, 0x55, 0x00, 0xe1, 0x71, 0x92,
        0x3a, 0x77, 0x3d, 0x5f, 0x15, 0x30, 0xf2, 0xed, 0x7e, 0x96,
        0x4c, 0xb2, 0xee, 0xdc, 0x29, 0xe9, 0xad, 0x2f, 0x3a, 0xfe,
        0x93, 0xb2, 0x81, 0x4f, 0x79, 0xf5, 0x00, 0x0f, 0xfc, 0x03,
        0x66, 0xc2, 0x51, 0xe6
    };

    p("plain:") printle(msg, 16);
    h1 = hmac_generate_256(key, 32, msg, 16);
    p(" hmac 256:") printle(h1, 32);
    p(" real 256:") printle(res256, 32);

    h2 = hmac_generate_512(key, 32, msg, 16);
    p(" hmac 512:") printle(h2, 64);
    p(" real 512:") printle(res512, 64);

    free(h1); free(h2);

    return 0;
}

