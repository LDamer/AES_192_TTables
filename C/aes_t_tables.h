#include <stdint.h>

typedef uint8_t u8;  
typedef uint16_t u16; 
typedef uint32_t u32;

typedef int8_t i8;  
typedef int16_t i16; 
typedef int32_t i32; 
int precompute_t_tables(u32 t_tables[4][256]);

int add_roundkey(u8 state[16], u8 roundkey[16]);

int enc_round(u32 t_tables[4][256], u8 state[16], u8 roundkey[16]);

int final_enc_round(u8 state[16], u8 roundkey[16], u8 ciphertext[16]);

int encrypt(u32 t_tables[4][256], u8 state[16], u8 roundkeys[13][16], u8 ciphertext[16]);

int key_schedule_192(u8 roundkeys[13][16], u8 key[24]);
