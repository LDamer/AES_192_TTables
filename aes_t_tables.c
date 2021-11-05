#include "aes_t_tables.h"
#include <string.h>

// AES S-Box
static const u8 sbox[256] =
    {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

// AES round constants
static const u8 rcon[11] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// ####################################
// code

int precompute_t_tables(u32 t_tables[4][256])
{
    for(int i = 0; i < 256; i++){
        // t_table[0]

        u16 first_row = sbox[i] < 128 ? sbox[i] << 1 : sbox[i] << 1 ^ 0x11B;

        // if S-Box[i] is greater than 128 the first bit is a 1 and we have to use modulo reduction
        // after multiplying with 2(or shifting by 1 to the left). In this case the modulo reduction is the same as
        // XOR with 0x11B(irreducible polynomial in AES)

        u16 second_row = sbox[i];

        u16 third_row = second_row;

        u16 fourth_row = sbox[i] < 128 ? sbox[i] << 1 ^ sbox[i] : sbox[i] << 1 ^ sbox[i] ^ 0x11B;

        // same as first row.
        // just instead of multiplying by 0x02 we have to multiply by 0x03, which is the same as multiplying by 0x02 and
        // adding the value again to it.(03 * a = 02*a + a = a << 1 ^ a)

        u32 res = first_row << 24 ^ second_row << 16 ^ third_row << 8 ^ fourth_row;
        t_tables[0][i] = res;

        // following is the same as t_table[0], just shorter and using the values calculated for t_tables[0]

        // t_tables[1]

        second_row = first_row;
        first_row = fourth_row;
        fourth_row = third_row;

        res = first_row << 24 ^ second_row << 16 ^ third_row << 8 ^ fourth_row;
        t_tables[1][i] = res;

        // t_tables[2]

        third_row = second_row;
        second_row = first_row;
        first_row = fourth_row;

        res = first_row << 24 ^ second_row << 16 ^ third_row << 8 ^ fourth_row;
        t_tables[2][i] = res;

        // t_tables[3]

        fourth_row = third_row;
        third_row = second_row;
        second_row = first_row;

        res = first_row << 24 ^ second_row << 16 ^ third_row << 8 ^ fourth_row;
        t_tables[3][i] = res;
    }

    return 0; 
}

int add_roundkey(u8 state[16], u8 roundkey[16])
{
 
    for(int i = 0; i < 16; i++){
        state[i] ^= roundkey[i];
    }
    return 0; 
}

int enc_round(u32 t_tables[4][256], u8 state[16], u8 roundkey[16])
{
   
    u32 res[4] = {0, 0, 0, 0};  // results for C0 - C15 before key-addition-layer and after mix-column-layer
    // res[0] holds 32-bit, describing C0-C3....res[1] holds 32-bit, describing C4-C7 ...

    // C0 - C3 after mix-columns layer with help of T-Tables
    res[0] ^= t_tables[0][state[0]] ^ t_tables[1][state[5]] ^ t_tables[2][state[10]] ^ t_tables[3][state[15]];

    // implementation of given formula

    // C4 - C7
    res[1] ^= t_tables[0][state[4]] ^ t_tables[1][state[9]] ^ t_tables[2][state[14]] ^ t_tables[3][state[3]];

    // C8 - C11
    res[2] ^= t_tables[0][state[8]] ^ t_tables[1][state[13]] ^ t_tables[2][state[2]] ^ t_tables[3][state[7]];

    // C12 - C15
    res[3] ^= t_tables[0][state[12]] ^ t_tables[1][state[1]] ^ t_tables[2][state[6]] ^ t_tables[3][state[11]];

    // ----overwriting state with the values after the mix-column-layer, stored in res----
    // state[0] should be the first byte of res[0]
    // state[1] should be the second byte of res[0]
    // state[2] should be the third byte of res[0]
    // ...
    // state[5] should be the second byte of res[1]
    // ...
    // state[15] should be the last byte of res[3]
    for(int i = 0; i < 16; i++){
        state[i] = (res[i / 4] & 256 - 1 << 24 - (i % 4) * 8) >> (3 - (i % 4)) * 8;
        // Bit masking
    }
    // ----add round key to complete AES Round----
    add_roundkey(state, roundkey);

    return 0; 
}


int final_enc_round(u8 state[16], u8 roundkey[16], u8 ciphertext[16])
{
    // ----Byte-substitution-layer----
    for(int i = 0; i < 16; i++){
        state[i] = sbox[state[i]];
    }
    // ----shift-row-layer-----

    // nothing happens with first row

    // second row
    u8 tmp = state[13];
    state[13] = state[1];
    state[1] = state[5];
    u8 tmp2 = state[9];
    state[9] = tmp;
    state[5] = tmp2;

    // third row
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    // fourth row
    tmp = state[3];
    state[3] = state[15];
    tmp2 = state[7];
    state[7] = tmp;
    tmp = state[11];
    state[11] = tmp2;
    state[15] = tmp;

    // ----key-addition-layer----
    add_roundkey(state, roundkey);

    // write the state into the ciphertext variable
    for(int i = 0; i < 16; i++){
        ciphertext[i] = state[i];
   }
    return 0; 
}


int encrypt(u32 t_tables[4][256], u8 plaintext[16], u8 roundkeys[13][16], u8 ciphertext[16])
{
    //----key-addition-layer before first round----
    add_roundkey(plaintext, roundkeys[0]);

    // round 1 to 11
    for(int i = 1; i < 12; i++){
        enc_round(t_tables, plaintext, roundkeys[i]);
    }
    // round 12(last round)
    final_enc_round(plaintext, roundkeys[12], ciphertext);

    return 0; 
}


// ----inner g-function of AES key-schedule----
u32 g(u32 val, u8 r){
    // write val byte wise in list b using bit masking.
    // b = [first byte, second byte, thrid byte, fourth byte]
    u32 b[4];
    for(int j = 0; j < 3; j++){
        b[j] = sbox[(val & (256 - 1 << (16 - j * 8))) >> (2 - j) * 8];
    }
    b[3] = sbox[(val & (256 - 1 << 24)) >> 24];
    b[0] ^= r;

    // return 32-bit as integer value, prepared for the xor in the key-schedule
    return 0 ^ b[0] << 24 ^ b[1] << 16 ^ b[2] << 8 ^ b[3];
}

#include <stdio.h>
int key_schedule_192(u8 roundkeys[13][16], u8 key[24])
{
    u32 w[52];  // prepare the word list of AES-192-key-schedule

    // compute words 0 - 5 directly from main key using bit masking
    // main key is given as hex list with 24 entries so that one entry holds 8 bit
    for(int i = 0; i < 6; i++){
        // extract the part of the main key(given as list) that is relevant for the current word
        // key_extract then holds a list with 4 entries(4 times 8 bit from main key)
        u8 key_extract[4];
        for(int j = 0; j < 4; j++){
            key_extract[j] = key[i * 4 + j];
        }
        u32 word = 0;
        // concatenate the extracted bits from main key to one 32-bit word
       for(int j = 0; j < 4; j++){
            word ^= (key_extract[j] << (24 - j * 8));
       }
       w[i] = word;
    }
    // compute words 6 to 51 recursively from words 0-5
    for(int i = 6; i < 52; i++){
        w[i] = i % 6 == 0 ? w[i - 6] ^ g(w[i - 1], rcon[i / 6 - 1]) : w[i - 6] ^ w[i - 1];
    }

    // extract the 13 round keys from the wordlist
    // put the 16 byte of each round key into a list
    for(int i = 0; i < 13; i++){
        //res stores the corresponding round key
        u8 res[16];

        // fill the list res with 16 bytes from the corresponding 4 words
        // so put the 128 bits from the 4 words into 16 bytes (16 entries), stored as list in res
        for(int j = 0; j < 4; j++){
            for(int k = 0; k < 4; k++){
                res[4*j+k] = (w[i * 4 + j] >> (24-8*k)) & 255;
            }
        }
        memcpy(roundkeys[i], res, 16);
    }
    return 0;
}
