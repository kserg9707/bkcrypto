#ifndef SHA512_HPP
#define SHA512_HPP

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include <algorithm>

#include "sha512_core.hpp"



namespace sha2
{

uint8_t* hash_generate_512_append(const uint8_t* data, size_t len, uint8_t is_end);

uint8_t hmac_set_key_512(const uint8_t* inkey, size_t inkeylen);

uint8_t* hmac_generate_512_append(const uint8_t* data, size_t len, uint8_t is_end);

uint8_t* hmac_generate_512(const uint8_t* inkey, size_t inkeylen, const uint8_t* data, size_t len);

}

#endif

