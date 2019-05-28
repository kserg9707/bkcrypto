#ifndef SHA512_CORE_HPP
#define SHA512_CORE_HPP

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include <algorithm>
//#include "sha512.hpp" //TODO

namespace sha2
{

//static const uint16_t test_le = 0x7357;
//static const bool is_le = ( *((uint8_t*)(&test_le)) == (test_le & 0xff) );

//static uint64_t host_to_be(uint64_t x);
//static uint64_t host_to_le(uint64_t x);
//static uint64_t change_endianess(uint64_t x);
//static uint64_t le_to_host(uint64_t x);
//static uint64_t be_to_host(uint64_t x);


//static inline uint64_t ROTR64(uint64_t x, uint64_t n);
//static inline uint64_t ROTL64(uint64_t x, uint64_t n);

//static inline uint64_t CH(uint64_t x, uint64_t y, uint64_t z);
//static inline uint64_t MAJ(uint64_t x, uint64_t y, uint64_t z);
//static inline uint64_t BSIG0(uint64_t x);
//static inline uint64_t BSIG1(uint64_t x);
//static inline uint64_t SSIG0(uint64_t x);
//static inline uint64_t SSIG1(uint64_t x);



class SHA512
{
public:
    static const size_t hash_size; // = 64;

private:
    static const size_t message_bs; // = 128; //bytes

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

    void init();
    void uninit();

    //returns len of rest message
    //calls process_block
    //append
    void parse_message(const uint8_t* message, size_t len);
    void pad_rest_message_block();

    //message cut in N blocks
    //first time Hlast -- memcpy(Hlast, H);
    void process_block();

    void finalize();

public:
    SHA512();
    SHA512(const SHA512& src) = delete;
    ~SHA512();

    SHA512& operator = (const SHA512& src) = delete;

    void append_message(const uint8_t* message, size_t len);

    void message_ended();

    uint8_t* get_res();
};

}

#endif

