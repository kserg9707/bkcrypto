#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include <algorithm>

#include "const.hpp"
#include "sha512_core.hpp"


static const uint16_t test_le = 0x7357;
static const bool is_le = ( *((uint8_t*)(&test_le)) == (test_le & 0xff) );

static uint64_t host_to_be(uint64_t x)
{
    if (!is_le) return x;

    uint8_t* x_ptr = (uint8_t*)(&x);
    return (((uint64_t)(x_ptr[0])) << 56) | (((uint64_t)(x_ptr[1])) << 48) | (((uint64_t)(x_ptr[2])) << 40) |
            (((uint64_t)(x_ptr[3])) << 32) | (((uint64_t)(x_ptr[4])) << 24) | (((uint64_t)(x_ptr[5])) << 16) |
            (((uint64_t)(x_ptr[6])) << 8) | (((uint64_t)(x_ptr[7])) << 0);
}
static uint64_t host_to_le(uint64_t x)
{
    if (is_le) return x;

    uint8_t* x_ptr = (uint8_t*)(&x);
    return (((uint64_t)(x_ptr[7])) << 56) | (((uint64_t)(x_ptr[6])) << 48) | (((uint64_t)(x_ptr[5])) << 40) |
            (((uint64_t)(x_ptr[4])) << 32) | (((uint64_t)(x_ptr[3])) << 24) | (((uint64_t)(x_ptr[2])) << 16) |
            (((uint64_t)(x_ptr[1])) << 8) | (((uint64_t)(x_ptr[0])) << 0);
}
static uint64_t change_endianess(uint64_t x)
{
    if (is_le) return host_to_be(x);
    return host_to_le(x);
}
static uint64_t le_to_host(uint64_t x)
{
    if (is_le) return x;
    return change_endianess(x);
}
static uint64_t be_to_host(uint64_t x)
{
    if (!is_le) return x;
    return change_endianess(x);
}


static inline uint64_t ROTR64(uint64_t x, uint64_t n)
{ return (x >> n) | (x << (64-n)); }
static inline uint64_t ROTL64(uint64_t x, uint64_t n)
{ return (x << n) | (x >> (64-n)); }

static inline uint64_t CH(uint64_t x, uint64_t y, uint64_t z)
{ return ((x & y) ^ ((~x) & z)); }

static inline uint64_t MAJ(uint64_t x, uint64_t y, uint64_t z)
{ return ((x & y) ^ (x & z) ^ (y & z)); }

static inline uint64_t BSIG0(uint64_t x)
{ return ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39); }

static inline uint64_t BSIG1(uint64_t x)
{ return ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41); }

static inline uint64_t SSIG0(uint64_t x)
{ return ROTR64(x, 1) ^ ROTR64(x, 8) ^ (x >> 7); }

static inline uint64_t SSIG1(uint64_t x)
{ return ROTR64(x, 19) ^ ROTR64(x, 61) ^ (x >> 6); }



const size_t sha2::SHA512::hash_size = 64;

const size_t sha2::SHA512::message_bs = 128; //bytes

//state:
uint64_t total_message_len = 0;
uint8_t* rest_message = NULL;
size_t rest_message_len = 0;

uint64_t* M = NULL;
const size_t M_len = 16;

uint64_t* Hlast = NULL;
const size_t Hlast_len = 8;
uint64_t* alph = NULL;
const size_t alph_len = 8;
uint64_t* W = NULL;
const size_t W_len = 80;

uint8_t* res = NULL;

void sha2::SHA512::init()
{
    rest_message = new uint8_t[message_bs];
    M = new uint64_t[M_len];
    Hlast = new uint64_t[Hlast_len];
    alph = new uint64_t[alph_len];
    W = new uint64_t[W_len];

    for (size_t i = 0; i < Hlast_len; ++i)
        Hlast[i] = sha512_H0[i];
    //TODO: memset 0
}

void sha2::SHA512::uninit()
{
    delete rest_message;
    delete M;
    delete Hlast;
    delete alph;
    delete W;
    if (res != NULL) delete res;
}

//returns len of rest message
//calls process_block
//append
void sha2::SHA512::parse_message(const uint8_t* message, size_t len)
{
    if (res != NULL)
    {
        uninit(); init();
    }
    size_t copy_to_rest = std::min(len, message_bs - rest_message_len);
    memcpy(
            rest_message + rest_message_len,
            message,
            copy_to_rest
    );
    rest_message_len += copy_to_rest;
    total_message_len += copy_to_rest;

    if (rest_message_len < message_bs)
        return;

    memset(M, 0, message_bs); //16*sizeof(uint64_t));
    memcpy(M, rest_message, message_bs);
    process_block();
    message += copy_to_rest;
    len -= copy_to_rest;

    while (len >= message_bs) //1024 bits, bs
    {
        memset(M, 0, message_bs); //16*sizeof(uint64_t));
        memcpy(M, message, message_bs);
        process_block();
        message += message_bs;
        len -= message_bs;
        total_message_len += message_bs;
    }

    memset(rest_message, 0, message_bs); //16*sizeof(uint64_t));
    memcpy(rest_message, message, len);
    rest_message_len = len;
    total_message_len += len;
}

void sha2::SHA512::pad_rest_message_block()
{
    if (res != NULL)
    {
        uninit(); init();
    }
    //size_t k = ((message_bs<<1) - len - 1 - 16) & (0x80 - 1); //(2*1024 - len - (1+7) - 128) % 1024

    uint8_t* padded = (uint8_t*)malloc(message_bs<<1);
    size_t padded_len = 0;

    memset(padded, 0, message_bs<<1); //16*sizeof(uint64_t));
    memcpy(padded, rest_message, rest_message_len);

    padded[rest_message_len++] = 0x80;
    padded_len = ((rest_message_len + 1 + 16 > 128) ? message_bs << 1 : message_bs);

    uint64_t l = host_to_be(total_message_len << 3); //bit length
    memcpy(padded + (padded_len - sizeof(uint64_t)), &l, sizeof(uint64_t));

    uint8_t* to_process = padded;
    while (padded_len > 0)
    {
        memset(M, 0, message_bs); //16*sizeof(uint64_t));
        memcpy(M, to_process, message_bs);
        process_block();
        to_process += message_bs;
        padded_len -= message_bs;
    }

    finalize();
}

//message cut in N blocks
//first time Hlast -- memcpy(Hlast, H);
void sha2::SHA512::process_block()
{
    for (size_t t = 0; t < M_len; ++t)
    {
        W[t] = host_to_be(M[t]);
        //printf("t: %d, W: %llx\n", t, W[t]);
    }
    for (size_t t = M_len; t < W_len; ++t)
    {
        W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
        //printf("t: %d, W[t-2]: %llx, SSIG1(W[t-2]): %llx, W[t-7]: %llx, W[t-15]: %llx, SSIG0[W[t-15]): %llx, W[t-16]: %llx, W: %llx\n",
        //        t, W[t-2], SSIG1(W[t-2]), W[t-7], W[t-15], SSIG0(W[t-15]), W[t-16], W[t]);
    }

    //DEBUG
    //for (int i = 0; i < 8; i++)
        //printf("%016llx ", Hlast[i]);
    //printf("\n");

    memcpy(alph, Hlast, 8*sizeof(uint64_t));
    //a -> [0], b -> [1], ..., h -> [7]

    uint64_t T1 = 0, T2 = 0;
    for (size_t t = 0; t < 80; ++t)
    {
        T1 = alph[7] + BSIG1(alph[4]) + CH(alph[4], alph[5], alph[6]) + sha512_K[t] + W[t];
        //printf("alph[7]: %llx, BSIG1(wv[4]): %llx, CH(alph[4],[5],[6]): %llx, W[%d]: %llx, T1: %llx\n",
        //        alph[7], BSIG1(alph[4]), CH(alph[4], alph[5], alph[6]), t,W[t], T1);
        T2 = BSIG0(alph[0]) + MAJ(alph[0], alph[1], alph[2]);
        for (size_t u = 7; u > 0; --u)
            alph[u] = alph[u-1];
        alph[4] += T1;
        alph[0] = T1 + T2;
    }

    for (size_t t = 0; t < 8; ++t)
        Hlast[t] += alph[t];

    //DEBUG
    //for (int i = 0; i < 8; i++)
    //    printf("%016llx ", Hlast[i]);
    //printf("\n");
}

void sha2::SHA512::finalize()
{
    for (size_t i = 0; i < Hlast_len; ++i)
        Hlast[i] = be_to_host(Hlast[i]);

    res = new uint8_t[hash_size];
    memset(res, 0, hash_size);

    memcpy(res, Hlast, hash_size);
}

sha2::SHA512::SHA512() { init(); }
//sha2::SHA512::SHA512(const SHA512& src) = delete;
sha2::SHA512::~SHA512() { uninit(); }

//sha2::SHA512& sha2::SHA512::operator = (const SHA512& src) = delete;

void sha2::SHA512::append_message(const uint8_t* message, size_t len)
{ parse_message(message, len); }

void sha2::SHA512::message_ended()
{ pad_rest_message_block(); }

uint8_t* sha2::SHA512::get_res()
{
    if (res == NULL) return NULL;
    uint8_t* r = new uint8_t[hash_size];
    memcpy(r, res, hash_size);
    return r;
}


/*int main()
{
    const char kek[] = "Some string passed to hash. Some string passed to hash. Some string passed to hash. Some string passed to hash. Some string passed to hash. ";
    sha2::SHA512 s;
    s.append_message((const uint8_t*)kek, strlen(kek));
    s.message_ended();
    uint8_t* res = s.get_res();
    for (size_t i = 0; i < sha2::SHA512::hash_size; ++i)
        printf("%02hhx", res[i]);
    printf("\n");
}*/

