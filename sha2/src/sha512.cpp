#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include <algorithm>

#include "sha512_core.hpp"

#include "sha512.hpp"



static sha2::SHA512* sha_res = NULL;
static sha2::SHA512* hmac_sha_res = NULL;

//inner variables
static uint8_t ipad[64] = {0x36};
static uint8_t opad[64] = {0x5c};
static uint8_t* key = NULL;
static size_t keylen = 0;
static uint8_t* _xor_block(uint8_t* res, const uint8_t* a, const uint8_t* b)
{
    uint8_t cpy[64];
    memcpy(cpy, a, 64);
    for (int i = 0; i < 64; i++)
        res[i] = a[i] ^ b[i];

    //XorArrays(res, a, b, 64);
    return res;
}

uint8_t* sha2::hash_generate_512_append(const uint8_t* data, size_t len, uint8_t is_end)
{
    if (sha_res == NULL)
        sha_res = new SHA512();

    sha_res->append_message(data, len);

    if (is_end)
    {
        sha_res->message_ended();
        return sha_res->get_res();
    }

    return NULL;
}


uint8_t sha2::hmac_set_key_512(const uint8_t* inkey, size_t inkeylen)
{
    if (hmac_sha_res == NULL)
        hmac_sha_res = new SHA512();

    if (inkeylen < 8 /*32*/ || inkeylen > 64)
    {
        fprintf(stderr, "hmac: wrong key size (%llu out of range [%d, %d])\n.", (uint64_t)inkeylen, 8, 64);
        return 1;
    }
    keylen = inkeylen;

    key = (uint8_t*)calloc(1, 64);
    memcpy(key, inkey, keylen);

    uint8_t key_xor_ipad[64];
    _xor_block(key_xor_ipad, key, ipad);

    uint8_t* concat = (uint8_t*)malloc(64);
    memcpy(concat, key_xor_ipad, 64);

    hmac_sha_res->append_message(concat, 64);
    //hash_generate_512_append(concat, 64, 0);
    free(concat);

    return 0;
}

uint8_t* sha2::hmac_generate_512_append(const uint8_t* data, size_t len, uint8_t is_end)
{
    //const size_t hashlen = SHA512::hash_size; //(mode == 256) ? 32 : 64;
    //SHA512 s1;
    hmac_sha_res->append_message(data, len);

    if (is_end)
        hmac_sha_res->message_ended();
    else
        return NULL;

    uint8_t* hash_ipad = hmac_sha_res->get_res(); //_hash_generate_append(mode, data, len, is_end);

    //if !is_end
    //if (hash_ipad == NULL)
    //    return NULL;

    uint8_t key_xor_opad[64];
    _xor_block(key_xor_opad, key, opad);

    uint8_t* concat2 = new uint8_t[64+SHA512::hash_size];
    memcpy(concat2, key_xor_opad, 64);
    memcpy(concat2+64, hash_ipad, SHA512::hash_size);

    memset(key, 0, keylen);
    keylen = 0;
    free(key); key = NULL;
    delete[] hash_ipad;
    //free(hash_ipad);

    SHA512 s;
    s.append_message(concat2, 64+s.hash_size);
    s.message_ended();
    delete[] concat2;
    return s.get_res();
    //return _hash_generate_append(mode, concat2, 64+SHA512::hash_size, 1);
}

uint8_t* sha2::hmac_generate_512(const uint8_t* inkey, size_t inkeylen, const uint8_t* data, size_t len)
{
    if (hmac_set_key_512(inkey, inkeylen))
        return NULL;
    return hmac_generate_512_append(data, len, 1);
}

int main()
{
    char key[] = "kekesloles";
    char msg[] = "some message";
    uint8_t* res = sha2::hmac_generate_512((uint8_t*)&(key[0]), strlen(key), (uint8_t*)&(msg[0]), strlen(msg));
    for (size_t i = 0; i < sha2::SHA512::hash_size; i++)
        printf("%02hhx", res[i]);
    printf("\n");
}

